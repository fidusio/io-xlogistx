package io.xlogistx.ffm.usecase;

import io.xlogistx.ffm.FFMUtil;
import io.xlogistx.ffm.usecase.OpenCLUtil.DevicePreference;
import org.zoxweb.shared.util.ParamUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * GPU-accelerated SHA-256 hashing via OpenCL + Java FFM.
 *
 * <p>Computes SHA-256 digests of multiple inputs in parallel on the GPU.
 * No native compilation required — the OpenCL kernel is compiled at runtime
 * by the GPU driver.</p>
 *
 * <h3>Usage — Programmatic</h3>
 * <pre>{@code
 * try (var sha = new OpenCLSHA256()) {
 *     // Single hash
 *     byte[] digest = sha.hash("hello".getBytes());
 *     System.out.println(sha.hex(digest));
 *
 *     // Batch hash (parallel on GPU)
 *     byte[][] inputs = { "hello".getBytes(), "world".getBytes() };
 *     byte[][] digests = sha.hashBatch(inputs);
 * }
 * }</pre>
 *
 * <h3>Usage — CLI</h3>
 * <pre>
 * OpenCLSHA256 text="hello world"
 * OpenCLSHA256 file=/path/to/file
 * OpenCLSHA256 batch="hello,world,foo,bar"
 * OpenCLSHA256 bench=1000000
 * </pre>
 */
public class OpenCLSHA256 implements AutoCloseable {

    // SHA-256 digest size
    private static final int DIGEST_SIZE = 32; // 256 bits = 32 bytes

    // OpenCL kernel — full SHA-256 implementation
    private static final String SHA256_KERNEL = """
        // SHA-256 round constants
        __constant uint K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Rotate right
        #define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
        #define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
        #define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
        #define EP0(x)  (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
        #define EP1(x)  (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
        #define SIG0(x) (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
        #define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

        // Read a big-endian 32-bit word from a byte array
        inline uint read_be32(__global const uchar* p) {
            return ((uint)p[0] << 24) | ((uint)p[1] << 16)
                 | ((uint)p[2] << 8)  | (uint)p[3];
        }

        // Write a big-endian 32-bit word to a byte array
        inline void write_be32(__global uchar* p, uint v) {
            p[0] = (uchar)(v >> 24);
            p[1] = (uchar)(v >> 16);
            p[2] = (uchar)(v >> 8);
            p[3] = (uchar)(v);
        }

        // SHA-256 kernel: each work-item hashes one padded message block sequence.
        //
        // Layout:
        //   padded_input: concatenation of all padded messages, each padded_len bytes
        //   output:       N * 32 bytes (one 256-bit digest per work-item)
        //   padded_len:   length of each padded message in bytes (multiple of 64)
        __kernel void sha256_hash(
                __global const uchar* padded_input,
                __global       uchar* output,
                uint padded_len)
        {
            int gid = get_global_id(0);
            __global const uchar* msg = padded_input + (ulong)gid * padded_len;

            // Initial hash values
            uint h0 = 0x6a09e667, h1 = 0xbb67ae85;
            uint h2 = 0x3c6ef372, h3 = 0xa54ff53a;
            uint h4 = 0x510e527f, h5 = 0x9b05688c;
            uint h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

            uint num_blocks = padded_len / 64;

            for (uint block = 0; block < num_blocks; block++) {
                __global const uchar* blk = msg + (ulong)block * 64;

                // Message schedule
                uint w[64];
                for (int i = 0; i < 16; i++)
                    w[i] = read_be32(blk + i * 4);
                for (int i = 16; i < 64; i++)
                    w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

                // Working variables
                uint a = h0, b = h1, c = h2, d = h3;
                uint e = h4, f = h5, g = h6, h = h7;

                // 64 rounds
                for (int i = 0; i < 64; i++) {
                    uint t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
                    uint t2 = EP0(a) + MAJ(a, b, c);
                    h = g; g = f; f = e; e = d + t1;
                    d = c; c = b; b = a; a = t1 + t2;
                }

                h0 += a; h1 += b; h2 += c; h3 += d;
                h4 += e; h5 += f; h6 += g; h7 += h;
            }

            // Write digest
            __global uchar* out = output + (ulong)gid * 32;
            write_be32(out +  0, h0); write_be32(out +  4, h1);
            write_be32(out +  8, h2); write_be32(out + 12, h3);
            write_be32(out + 16, h4); write_be32(out + 20, h5);
            write_be32(out + 24, h6); write_be32(out + 28, h7);
        }
        """;

    private final FFMUtil.Library cl;
    private final Arena arena;
    private final MemorySegment context;
    private final MemorySegment queue;
    private final MemorySegment program;
    private final MemorySegment kernel;
    private final MemorySegment device;
    private final String deviceName;
    private final String deviceVendor;
    private final boolean isGpu;
    private final boolean svmSupported;
    private final boolean svmFineGrain;

    /**
     * Initializes OpenCL: discovers GPU, creates context, compiles SHA-256 kernel.
     * Falls back to any available device if no GPU is found.
     */
    public OpenCLSHA256() throws Throwable {
        this(OpenCLUtil.findLibrary(), "/usr/include/CL/cl.h", DevicePreference.GPU);
    }

    /**
     * Initializes OpenCL with explicit device preference.
     *
     * @param preference GPU, CPU, or ANY
     */
    public OpenCLSHA256(DevicePreference preference) throws Throwable {
        this(OpenCLUtil.findLibrary(), "/usr/include/CL/cl.h", preference);
    }

    /**
     * Initializes OpenCL with explicit library, header paths, and device preference.
     */
    public OpenCLSHA256(String libPath, String headerPath, DevicePreference preference) throws Throwable {
        cl = FFMUtil.library(libPath)
                .header(headerPath)
                .includePath("/usr/include")
                .load();
        arena = cl.arena();

        // --- Discover all platforms and find a device matching the preference ---
        long preferredType = preference.clType();

        var numPlatBuf = arena.allocate(ValueLayout.JAVA_INT);
        OpenCLUtil.check("clGetPlatformIDs(count)",
                (int) cl.invoke("clGetPlatformIDs", 0, MemorySegment.NULL, numPlatBuf));
        int numPlatforms = numPlatBuf.get(ValueLayout.JAVA_INT, 0);
        if (numPlatforms == 0)
            throw new RuntimeException("No OpenCL platforms found.");

        var platArray = arena.allocate(ValueLayout.ADDRESS, numPlatforms);
        OpenCLUtil.check("clGetPlatformIDs",
                (int) cl.invoke("clGetPlatformIDs", numPlatforms, platArray, MemorySegment.NULL));

        // Search all platforms for a device matching the requested type
        var devBuf = arena.allocate(ValueLayout.ADDRESS);
        boolean found = false;
        for (int p = 0; p < numPlatforms; p++) {
            MemorySegment plat = platArray.getAtIndex(ValueLayout.ADDRESS, p);
            int err = (int) cl.invoke("clGetDeviceIDs",
                    plat, preferredType, 1, devBuf, MemorySegment.NULL);
            if (err == OpenCLUtil.CL_SUCCESS) {
                found = true;
                break;
            }
        }
        if (!found) {
            String hint = switch (preference) {
                case CPU -> "No OpenCL CPU device found. Install a CPU runtime: sudo apt install pocl-opencl-icd";
                case GPU -> "No OpenCL GPU device found. Install a GPU driver with OpenCL support.";
                case ANY -> "No OpenCL devices found. Install an OpenCL ICD: sudo apt install ocl-icd-libopencl1";
            };
            throw new RuntimeException(hint);
        }
        device = devBuf.get(ValueLayout.ADDRESS, 0);

        // --- Query device info ---
        deviceName = OpenCLUtil.queryDeviceString(cl, arena, device, OpenCLUtil.CL_DEVICE_NAME);
        deviceVendor = OpenCLUtil.queryDeviceString(cl, arena, device, OpenCLUtil.CL_DEVICE_VENDOR);
        long deviceType = OpenCLUtil.queryDeviceLong(cl, arena, device, OpenCLUtil.CL_DEVICE_TYPE);
        isGpu = (deviceType & OpenCLUtil.CL_DEVICE_TYPE_GPU_BIT) != 0;

        // --- SVM capability detection ---
        long svmCaps = OpenCLUtil.queryDeviceLong(cl, arena, device, OpenCLUtil.CL_DEVICE_SVM_CAPABILITIES);
        svmSupported = (svmCaps & OpenCLUtil.CL_DEVICE_SVM_COARSE_GRAIN_BUFFER) != 0;
        svmFineGrain = (svmCaps & OpenCLUtil.CL_DEVICE_SVM_FINE_GRAIN_BUFFER) != 0;

        // --- Context ---
        var errBuf = arena.allocate(ValueLayout.JAVA_INT);
        context = (MemorySegment) cl.invoke("clCreateContext",
                MemorySegment.NULL, 1, devBuf, MemorySegment.NULL, MemorySegment.NULL, errBuf);
        OpenCLUtil.check("clCreateContext", errBuf.get(ValueLayout.JAVA_INT, 0));

        // --- Command queue ---
        queue = (MemorySegment) cl.invoke("clCreateCommandQueueWithProperties",
                context, device, MemorySegment.NULL, errBuf);
        OpenCLUtil.check("clCreateCommandQueue", errBuf.get(ValueLayout.JAVA_INT, 0));

        // --- Compile kernel ---
        var srcSeg = arena.allocateFrom(SHA256_KERNEL);
        var srcPtr = arena.allocate(ValueLayout.ADDRESS);
        srcPtr.set(ValueLayout.ADDRESS, 0, srcSeg);

        program = (MemorySegment) cl.invoke("clCreateProgramWithSource",
                context, 1, srcPtr, MemorySegment.NULL, errBuf);
        OpenCLUtil.check("clCreateProgramWithSource", errBuf.get(ValueLayout.JAVA_INT, 0));

        int buildErr = (int) cl.invoke("clBuildProgram",
                program, 1, devBuf, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL);
        if (buildErr != OpenCLUtil.CL_SUCCESS) {
            throw new RuntimeException("clBuildProgram failed (error " + buildErr + "): "
                    + OpenCLUtil.getBuildLog(cl, arena, program, devBuf));
        }

        kernel = (MemorySegment) cl.invoke("clCreateKernel",
                program, arena.allocateFrom("sha256_hash"), errBuf);
        OpenCLUtil.check("clCreateKernel", errBuf.get(ValueLayout.JAVA_INT, 0));
    }


    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /** Returns true if the device is a GPU, false for CPU/other. */
    public boolean isGpu() { return isGpu; }

    /** Returns the OpenCL device name (e.g. "Intel HD Graphics 630"). */
    public String deviceName() { return deviceName; }

    /** Returns the device vendor (e.g. "Intel", "NVIDIA"). */
    public String deviceVendor() { return deviceVendor; }

    /** Returns true if SVM (Shared Virtual Memory) is available — enables zero-copy. */
    public boolean svmSupported() { return svmSupported; }

    /** Returns true if fine-grain SVM is available (no explicit map/unmap needed). */
    public boolean svmFineGrain() { return svmFineGrain; }

    /** Returns a one-line device summary. */
    public String deviceInfo() {
        String svm = svmFineGrain ? " | SVM: fine-grain (zero-copy)"
                : svmSupported ? " | SVM: coarse-grain"
                : " | SVM: not supported (copy mode)";
        return (isGpu ? "GPU" : "CPU") + ": " + deviceName + " (" + deviceVendor + ")" + svm;
    }

    /**
     * Hashes a single input on the GPU.
     *
     * @param input raw bytes to hash
     * @return 32-byte SHA-256 digest
     */
    public byte[] hash(byte[] input) throws Throwable {
        byte[][] results = hashBatch(new byte[][]{input});
        return results[0];
    }

    /**
     * Hashes multiple inputs in parallel on the GPU.
     * All inputs are padded to the same block-aligned length and dispatched
     * as a single kernel invocation with one work-item per input.
     *
     * @param inputs array of raw byte arrays to hash
     * @return array of 32-byte SHA-256 digests, one per input
     */
    public byte[][] hashBatch(byte[][] inputs) throws Throwable {
        int count = inputs.length;
        if (count == 0) return new byte[0][];

        // Pad all inputs to SHA-256 spec (same padded length for uniform dispatch)
        int maxLen = 0;
        for (byte[] in : inputs) maxLen = Math.max(maxLen, in.length);
        int paddedLen = paddedSize(maxLen);

        // Build flat padded buffer: count * paddedLen bytes
        byte[] flatInput = new byte[count * paddedLen];
        for (int i = 0; i < count; i++) {
            padMessage(inputs[i], flatInput, i * paddedLen, paddedLen);
        }

        int outputSize = count * DIGEST_SIZE;

        // Use SVM zero-copy only when fine-grain is available (truly shared memory).
        // Coarse-grain SVM still requires explicit map/unmap and is no faster than copy.
        return svmFineGrain
                ? hashBatchSVM(flatInput, paddedLen, count, outputSize)
                : hashBatchCopy(flatInput, paddedLen, count, outputSize);
    }

    /**
     * SVM fine-grain path — true zero-copy when CPU and GPU share memory.
     * Both sides see the same physical memory. No clCreateBuffer, no
     * clEnqueueReadBuffer, no map/unmap — just write, dispatch, read.
     */
    private byte[][] hashBatchSVM(byte[] flatInput, int paddedLen,
                                   int count, int outputSize) throws Throwable {
        var svmInput = (MemorySegment) cl.invoke("clSVMAlloc",
                context, OpenCLUtil.CL_MEM_READ_ONLY, (long) flatInput.length, 0);
        if (svmInput.address() == 0)
            throw new RuntimeException("clSVMAlloc(input) returned NULL");

        var svmOutput = (MemorySegment) cl.invoke("clSVMAlloc",
                context, OpenCLUtil.CL_MEM_WRITE_ONLY, (long) outputSize, 0);
        if (svmOutput.address() == 0) {
            cl.invoke("clSVMFree", context, svmInput);
            throw new RuntimeException("clSVMAlloc(output) returned NULL");
        }

        try {
            // Reinterpret SVM pointers to usable sizes
            var inputSeg = svmInput.reinterpret(flatInput.length);
            var outputSeg = svmOutput.reinterpret(outputSize);

            // Fine-grain: write directly to shared memory
            inputSeg.copyFrom(MemorySegment.ofArray(flatInput));

            // Set kernel args via SVM pointers
            OpenCLUtil.setKernelArgSVM(cl, kernel, 0, svmInput);
            OpenCLUtil.setKernelArgSVM(cl, kernel, 1, svmOutput);
            OpenCLUtil.setKernelArgInt(cl, arena, kernel, 2, paddedLen);

            // Dispatch
            var globalSize = arena.allocate(ValueLayout.JAVA_LONG);
            globalSize.set(ValueLayout.JAVA_LONG, 0, count);
            OpenCLUtil.check("clEnqueueNDRangeKernel",
                    (int) cl.invoke("clEnqueueNDRangeKernel",
                            queue, kernel, 1,
                            MemorySegment.NULL, globalSize, MemorySegment.NULL,
                            0, MemorySegment.NULL, MemorySegment.NULL));

            // Wait for kernel, then read directly from shared memory
            OpenCLUtil.check("clFinish", (int) cl.invoke("clFinish", queue));

            // Extract digests — no copy, just slice the shared segment
            byte[][] digests = new byte[count][];
            for (int i = 0; i < count; i++) {
                digests[i] = outputSeg.asSlice((long) i * DIGEST_SIZE, DIGEST_SIZE)
                        .toArray(ValueLayout.JAVA_BYTE);
            }
            return digests;
        } finally {
            cl.invoke("clSVMFree", context, svmInput);
            cl.invoke("clSVMFree", context, svmOutput);
        }
    }

    /**
     * Copy path — universal fallback for discrete GPUs or devices without SVM.
     * Uses clCreateBuffer + clEnqueueReadBuffer (two explicit copies).
     */
    private byte[][] hashBatchCopy(byte[] flatInput, int paddedLen,
                                    int count, int outputSize) throws Throwable {
        var errBuf = arena.allocate(ValueLayout.JAVA_INT);

        // --- Input buffer ---
        var inputSeg = arena.allocate(flatInput.length);
        inputSeg.copyFrom(MemorySegment.ofArray(flatInput));
        var clInput = (MemorySegment) cl.invoke("clCreateBuffer",
                context, OpenCLUtil.CL_MEM_READ_ONLY | OpenCLUtil.CL_MEM_COPY_HOST_PTR,
                (long) flatInput.length, inputSeg, errBuf);
        OpenCLUtil.check("clCreateBuffer(input)", errBuf.get(ValueLayout.JAVA_INT, 0));

        // --- Output buffer ---
        var clOutput = (MemorySegment) cl.invoke("clCreateBuffer",
                context, OpenCLUtil.CL_MEM_WRITE_ONLY,
                (long) outputSize, MemorySegment.NULL, errBuf);
        OpenCLUtil.check("clCreateBuffer(output)", errBuf.get(ValueLayout.JAVA_INT, 0));

        try {
            // --- Set kernel args ---
            OpenCLUtil.setKernelArgAddr(cl, arena, kernel, 0, clInput);
            OpenCLUtil.setKernelArgAddr(cl, arena, kernel, 1, clOutput);
            OpenCLUtil.setKernelArgInt(cl, arena, kernel, 2, paddedLen);

            // --- Enqueue ---
            var globalSize = arena.allocate(ValueLayout.JAVA_LONG);
            globalSize.set(ValueLayout.JAVA_LONG, 0, count);

            OpenCLUtil.check("clEnqueueNDRangeKernel",
                    (int) cl.invoke("clEnqueueNDRangeKernel",
                            queue, kernel, 1,
                            MemorySegment.NULL, globalSize, MemorySegment.NULL,
                            0, MemorySegment.NULL, MemorySegment.NULL));

            // --- Read back (explicit copy from GPU) ---
            var resultSeg = arena.allocate(outputSize);
            OpenCLUtil.check("clEnqueueReadBuffer",
                    (int) cl.invoke("clEnqueueReadBuffer",
                            queue, clOutput, 1 /* blocking */,
                            0L, (long) outputSize, resultSeg,
                            0, MemorySegment.NULL, MemorySegment.NULL));

            OpenCLUtil.check("clFinish", (int) cl.invoke("clFinish", queue));

            // --- Extract digests ---
            byte[][] digests = new byte[count][];
            for (int i = 0; i < count; i++) {
                digests[i] = resultSeg.asSlice((long) i * DIGEST_SIZE, DIGEST_SIZE)
                        .toArray(ValueLayout.JAVA_BYTE);
            }
            return digests;
        } finally {
            cl.invoke("clReleaseMemObject", clInput);
            cl.invoke("clReleaseMemObject", clOutput);
        }
    }

    /** Returns the hex string of a digest. */
    public static String hex(byte[] digest) {
        return HexFormat.of().formatHex(digest);
    }

    @Override
    public void close() {
        try {
            cl.invoke("clReleaseKernel", kernel);
            cl.invoke("clReleaseProgram", program);
            cl.invoke("clReleaseCommandQueue", queue);
            cl.invoke("clReleaseContext", context);
        } catch (Throwable ignored) {}
        cl.close();
    }


    // =========================================================================
    // SHA-256 PADDING (done on CPU before sending to GPU)
    // =========================================================================

    /** Computes the padded size for a message of the given length (multiple of 64). */
    private static int paddedSize(int msgLen) {
        // message + 1 byte (0x80) + padding + 8 bytes (length)
        // must be multiple of 64 (512 bits)
        int total = msgLen + 1 + 8; // min space needed
        return ((total + 63) / 64) * 64;
    }

    /**
     * Pads a message into the destination buffer per SHA-256 spec:
     * message || 0x80 || zeros || big-endian 64-bit bit-length
     */
    private static void padMessage(byte[] msg, byte[] dest, int offset, int paddedLen) {
        // Copy message
        System.arraycopy(msg, 0, dest, offset, msg.length);
        // Append 0x80
        dest[offset + msg.length] = (byte) 0x80;
        // Zeros are already there (array initialized to 0)
        // Write bit length as big-endian 64-bit at the end
        long bitLen = (long) msg.length * 8;
        int lenOffset = offset + paddedLen - 8;
        for (int i = 7; i >= 0; i--) {
            dest[lenOffset + i] = (byte) (bitLen & 0xFF);
            bitLen >>= 8;
        }
    }


    // =========================================================================
    // CLI
    // =========================================================================

    private static final String USAGE = """
            OpenCLSHA256 — GPU-accelerated SHA-256 hashing via OpenCL + FFM.

            Usage:
              OpenCLSHA256 text="hello world"
              OpenCLSHA256 file=/path/to/file
              OpenCLSHA256 batch="hello,world,foo,bar"
              OpenCLSHA256 bench=<count>

            Options:
              text=<string>     Hash a single string.
              file=<path>       Hash a file's contents.
              batch=<csv>       Hash multiple comma-separated strings in parallel.
              bench=<count>     Benchmark: hash <count> copies of "benchmark" in parallel.
              lib=<path>        Override libOpenCL.so path.
              header=<path>     Override cl.h path (default: /usr/include/CL/cl.h).
              device=gpu|cpu|any  Force GPU, CPU, or any device (default: gpu).
            """;

    public static void main(String[] args) throws Throwable {
        if (args.length == 0) {
            System.out.println(USAGE);
            return;
        }

        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String text = params.stringValue("text", true);
        String file = params.stringValue("file", true);
        String batch = params.stringValue("batch", true);
        String bench = params.stringValue("bench", true);
        String lib = params.stringValue("lib", true);
        String header = params.stringValue("header", true);
        String deviceStr = params.stringValue("device", true);

        String libPath = lib != null ? lib : OpenCLUtil.findLibrary();
        String headerPath = header != null ? header : "/usr/include/CL/cl.h";
        DevicePreference pref = DevicePreference.GPU;
        if (deviceStr != null) {
            pref = switch (deviceStr.toLowerCase()) {
                case "cpu" -> DevicePreference.CPU;
                case "any" -> DevicePreference.ANY;
                default -> DevicePreference.GPU;
            };
        }

        try (var sha = new OpenCLSHA256(libPath, headerPath, pref)) {
            System.out.println("Device: " + sha.deviceInfo());
            System.out.println();

            if (text != null) {
                long start = System.nanoTime();
                byte[] digest = sha.hash(text.getBytes(StandardCharsets.UTF_8));
                double ms = (System.nanoTime() - start) / 1_000_000.0;
                System.out.printf("%s  \"%s\"  [%.2f ms]%n", hex(digest), text, ms);
            }

            if (file != null) {
                byte[] data = Files.readAllBytes(Path.of(file));
                long start = System.nanoTime();
                byte[] digest = sha.hash(data);
                double ms = (System.nanoTime() - start) / 1_000_000.0;
                System.out.printf("%s  %s (%,d bytes)  [%.2f ms]%n",
                        hex(digest), file, data.length, ms);
            }

            if (batch != null) {
                String[] parts = batch.split(",");
                byte[][] inputs = new byte[parts.length][];
                for (int i = 0; i < parts.length; i++)
                    inputs[i] = parts[i].trim().getBytes(StandardCharsets.UTF_8);

                long start = System.nanoTime();
                byte[][] digests = sha.hashBatch(inputs);
                double ms = (System.nanoTime() - start) / 1_000_000.0;

                for (int i = 0; i < parts.length; i++)
                    System.out.println(hex(digests[i]) + "  \"" + parts[i].trim() + "\"");
                System.out.printf("[%d hashes in %.2f ms]%n", parts.length, ms);
            }

            if (bench != null) {
                int count = Integer.parseInt(bench);
                byte[] sample = "benchmark".getBytes(StandardCharsets.UTF_8);
                byte[][] inputs = new byte[count][];
                for (int i = 0; i < count; i++) inputs[i] = sample;

                // Warmup
                sha.hashBatch(inputs.length > 1000 ? new byte[][]{sample} : inputs);

                long start = System.nanoTime();
                byte[][] digests = sha.hashBatch(inputs);
                long elapsed = System.nanoTime() - start;

                double ms = elapsed / 1_000_000.0;
                double rate = count / (ms / 1000.0);
                System.out.printf("Hashed %,d inputs in %.2f ms (%.0f hashes/sec)%n",
                        count, ms, rate);
                System.out.println("Sample digest: " + hex(digests[0]));
            }
        }
    }
}
