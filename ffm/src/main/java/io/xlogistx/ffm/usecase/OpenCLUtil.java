package io.xlogistx.ffm.usecase;

import io.xlogistx.ffm.FFMUtil;
import org.zoxweb.shared.util.ParamUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * General-purpose OpenCL helpers shared by use-cases built on top of {@link FFMUtil}.
 *
 * <p>All members are static and stateless — callers pass in their own
 * {@link FFMUtil.Library}, {@link Arena}, and OpenCL handles.</p>
 */
public final class OpenCLUtil {

    private OpenCLUtil() {}

    // =========================================================================
    // OPENCL CONSTANTS
    // =========================================================================

    public static final int  CL_SUCCESS                         = 0;

    // Device types
    public static final long CL_DEVICE_TYPE_CPU_BIT             = 2L;
    public static final long CL_DEVICE_TYPE_GPU_BIT             = 4L;
    public static final long CL_DEVICE_TYPE_ALL                 = 0xFFFFFFFFL;

    // Memory flags
    public static final long CL_MEM_READ_ONLY                   = 1L << 2;
    public static final long CL_MEM_WRITE_ONLY                  = 1L << 1;
    public static final long CL_MEM_COPY_HOST_PTR               = 1L << 5;

    // Device info params
    public static final int  CL_DEVICE_TYPE                     = 0x1000;
    public static final int  CL_DEVICE_MAX_COMPUTE_UNITS        = 0x1002;
    public static final int  CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS = 0x1003;
    public static final int  CL_DEVICE_MAX_WORK_GROUP_SIZE      = 0x1004;
    public static final int  CL_DEVICE_MAX_CLOCK_FREQUENCY      = 0x100C;
    public static final int  CL_DEVICE_ADDRESS_BITS             = 0x100D;
    public static final int  CL_DEVICE_MAX_MEM_ALLOC_SIZE       = 0x1010;
    public static final int  CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE= 0x101D;
    public static final int  CL_DEVICE_GLOBAL_MEM_CACHE_SIZE    = 0x101E;
    public static final int  CL_DEVICE_GLOBAL_MEM_SIZE          = 0x101F;
    public static final int  CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE = 0x1020;
    public static final int  CL_DEVICE_LOCAL_MEM_SIZE           = 0x1023;
    public static final int  CL_DEVICE_NAME                     = 0x102B;
    public static final int  CL_DEVICE_VENDOR                   = 0x102C;
    public static final int  CL_DRIVER_VERSION                  = 0x102D;
    public static final int  CL_DEVICE_PROFILE                  = 0x102E;
    public static final int  CL_DEVICE_VERSION                  = 0x102F;
    public static final int  CL_DEVICE_EXTENSIONS               = 0x1030;
    public static final int  CL_DEVICE_HOST_UNIFIED_MEMORY      = 0x1035;
    public static final int  CL_DEVICE_OPENCL_C_VERSION         = 0x103D;
    public static final int  CL_DEVICE_SVM_CAPABILITIES         = 0x1053;

    // SVM capability bits
    public static final long CL_DEVICE_SVM_COARSE_GRAIN_BUFFER  = 1L;
    public static final long CL_DEVICE_SVM_FINE_GRAIN_BUFFER    = 1L << 1;

    // Program build info
    public static final int  CL_PROGRAM_BUILD_LOG               = 2;


    /** Device preference for OpenCL device selection. */
    public enum DevicePreference {
        GPU(CL_DEVICE_TYPE_GPU_BIT),
        CPU(CL_DEVICE_TYPE_CPU_BIT),
        ANY(CL_DEVICE_TYPE_ALL);

        private final long clType;

        DevicePreference(long clType) { this.clType = clType; }

        /** Returns the OpenCL device-type bitmask for this preference. */
        public long clType() { return clType; }
    }


    // =========================================================================
    // ERROR HANDLING
    // =========================================================================

    /** Throws if {@code err != CL_SUCCESS}, with the call name in the message. */
    public static void check(String call, int err) {
        if (err != CL_SUCCESS)
            throw new RuntimeException(call + " failed with error code " + err);
    }


    // =========================================================================
    // LIBRARY DISCOVERY
    // =========================================================================

    private static final String[] DEFAULT_LIB_PATHS = {
            "/usr/lib/x86_64-linux-gnu/libOpenCL.so.1",
            "/usr/lib/aarch64-linux-gnu/libOpenCL.so.1",
            "/usr/lib/libOpenCL.so.1",
            "/usr/local/lib/libOpenCL.so.1",
            "/opt/homebrew/lib/libOpenCL.dylib"
    };

    /**
     * Returns the first existing path from the default libOpenCL locations.
     * @throws RuntimeException if none are found.
     */
    public static String findLibrary() {
        for (String path : DEFAULT_LIB_PATHS) {
            if (Files.exists(Path.of(path))) return path;
        }
        throw new RuntimeException("libOpenCL not found — install an OpenCL ICD "
                + "(e.g. apt install ocl-icd-libopencl1)");
    }


    // =========================================================================
    // DEVICE INFO
    // =========================================================================

    /**
     * Queries a string-valued device info parameter (e.g. {@link #CL_DEVICE_NAME}).
     * Returns {@code "<unknown>"} if the parameter is not available.
     */
    public static String queryDeviceString(FFMUtil.Library cl, Arena arena,
                                           MemorySegment device, int param) throws Throwable {
        var sizeBuf = arena.allocate(ValueLayout.JAVA_LONG);
        cl.invoke("clGetDeviceInfo", device, param,
                0L, MemorySegment.NULL, sizeBuf);
        long size = sizeBuf.get(ValueLayout.JAVA_LONG, 0);
        if (size <= 1) return "<unknown>";
        var buf = arena.allocate(size);
        cl.invoke("clGetDeviceInfo", device, param, size, buf, MemorySegment.NULL);
        return buf.getString(0).trim();
    }

    /** Queries a long-valued (cl_ulong / size_t on LP64) device info parameter. */
    public static long queryDeviceLong(FFMUtil.Library cl, Arena arena,
                                       MemorySegment device, int param) throws Throwable {
        var buf = arena.allocate(ValueLayout.JAVA_LONG);
        cl.invoke("clGetDeviceInfo", device, param,
                (long) Long.BYTES, buf, MemorySegment.NULL);
        return buf.get(ValueLayout.JAVA_LONG, 0);
    }

    /** Queries a 32-bit integer (cl_uint / cl_bool) device info parameter. */
    public static int queryDeviceInt(FFMUtil.Library cl, Arena arena,
                                     MemorySegment device, int param) throws Throwable {
        var buf = arena.allocate(ValueLayout.JAVA_INT);
        cl.invoke("clGetDeviceInfo", device, param,
                (long) Integer.BYTES, buf, MemorySegment.NULL);
        return buf.get(ValueLayout.JAVA_INT, 0);
    }


    // =========================================================================
    // DEVICE FEATURE SUMMARY
    // =========================================================================

    /**
     * Snapshot of an OpenCL device's capabilities — name, memory topology,
     * compute resources, version strings, and SVM support.
     *
     * @param name               Device product name (e.g. "Intel Iris Xe Graphics").
     * @param vendor             Vendor string (e.g. "Intel", "NVIDIA Corporation").
     * @param version            OpenCL version reported by the device (e.g. "OpenCL 3.0 NEO").
     * @param driverVersion      Vendor driver version string.
     * @param profile            "FULL_PROFILE" or "EMBEDDED_PROFILE".
     * @param openclCVersion     OpenCL C language version supported.
     * @param deviceType         Raw cl_device_type bitmask.
     * @param gpu                True if the device advertises the GPU bit.
     * @param cpu                True if the device advertises the CPU bit.
     * @param computeUnits       Number of parallel compute units (cores / SMs / CUs).
     * @param maxWorkGroupSize   Max work-items per work-group.
     * @param maxClockFreqMHz    Max clock frequency in MHz.
     * @param addressBits        Pointer width (32 or 64).
     * @param globalMemBytes     Total device (global) memory in bytes.
     * @param maxMemAllocBytes   Largest single buffer allocation allowed.
     * @param localMemBytes      Per-workgroup local (shared) memory in bytes.
     * @param constantMemBytes   Max constant buffer size in bytes.
     * @param globalCacheBytes   Size of the global memory cache in bytes (0 if none).
     * @param cachelineBytes     Cache line size in bytes (0 if none).
     * @param unifiedMemory      True if the device shares the host's physical RAM
     *                           (integrated GPU / APU). False means dedicated VRAM.
     * @param svmSupported       True if coarse-grain SVM is available.
     * @param svmFineGrain       True if fine-grain SVM is available (true zero-copy).
     * @param extensions         Space-separated list of supported OpenCL extensions.
     */
    public record DeviceInfo(
            String name,
            String vendor,
            String version,
            String driverVersion,
            String profile,
            String openclCVersion,
            long deviceType,
            boolean gpu,
            boolean cpu,
            int computeUnits,
            long maxWorkGroupSize,
            int maxClockFreqMHz,
            int addressBits,
            long globalMemBytes,
            long maxMemAllocBytes,
            long localMemBytes,
            long constantMemBytes,
            long globalCacheBytes,
            long cachelineBytes,
            boolean unifiedMemory,
            boolean svmSupported,
            boolean svmFineGrain,
            String extensions) {

        /** "dedicated" if the device has its own VRAM, "shared" if memory is host-unified. */
        public String memoryTopology() {
            return unifiedMemory ? "shared" : "dedicated";
        }

        /** Short, single-line description. */
        public String summary() {
            return String.format(
                    "%s: %s (%s) | %d CUs @ %d MHz | %s mem: %s (max alloc %s) | %s | %s",
                    gpu ? "GPU" : cpu ? "CPU" : "DEV",
                    name, vendor,
                    computeUnits, maxClockFreqMHz,
                    memoryTopology(), humanBytes(globalMemBytes), humanBytes(maxMemAllocBytes),
                    version,
                    svmFineGrain ? "SVM fine-grain"
                            : svmSupported ? "SVM coarse-grain"
                            : "no SVM");
        }

        /** Multi-line human-readable report. */
        public String prettyReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("Device:          ").append(name).append('\n');
            sb.append("Vendor:          ").append(vendor).append('\n');
            sb.append("Type:            ").append(gpu ? "GPU" : cpu ? "CPU" : "OTHER")
                    .append(" (0x").append(Long.toHexString(deviceType)).append(")\n");
            sb.append("OpenCL version:  ").append(version).append('\n');
            sb.append("OpenCL C:        ").append(openclCVersion).append('\n');
            sb.append("Driver:          ").append(driverVersion).append('\n');
            sb.append("Profile:         ").append(profile).append('\n');
            sb.append("Compute units:   ").append(computeUnits).append('\n');
            sb.append("Max clock:       ").append(maxClockFreqMHz).append(" MHz\n");
            sb.append("Max work-group:  ").append(maxWorkGroupSize).append('\n');
            sb.append("Address bits:    ").append(addressBits).append('\n');
            sb.append("Memory topology: ").append(memoryTopology())
                    .append(unifiedMemory ? " (host-unified / integrated)" : " (discrete VRAM)")
                    .append('\n');
            sb.append("Global memory:   ").append(humanBytes(globalMemBytes)).append('\n');
            sb.append("Max allocation:  ").append(humanBytes(maxMemAllocBytes)).append('\n');
            sb.append("Local memory:    ").append(humanBytes(localMemBytes)).append('\n');
            sb.append("Constant buffer: ").append(humanBytes(constantMemBytes)).append('\n');
            sb.append("Global cache:    ").append(humanBytes(globalCacheBytes))
                    .append(" (line ").append(cachelineBytes).append(" B)\n");
            sb.append("SVM:             ")
                    .append(svmFineGrain ? "fine-grain (zero-copy)"
                            : svmSupported ? "coarse-grain"
                            : "not supported").append('\n');
            sb.append("Extensions:      ").append(extensions);
            return sb.toString();
        }
    }

    /** Formats a byte count as B/KiB/MiB/GiB with 2 decimals. */
    public static String humanBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format("%.2f KiB", kb);
        double mb = kb / 1024.0;
        if (mb < 1024) return String.format("%.2f MiB", mb);
        return String.format("%.2f GiB", mb / 1024.0);
    }

    /**
     * Queries all features of the given device in one shot. Any individual
     * field that fails to query falls back to a sensible default
     * ({@code "<unknown>"} for strings, 0 for numbers, false for booleans).
     */
    public static DeviceInfo queryDeviceInfo(FFMUtil.Library cl, Arena arena,
                                             MemorySegment device) {
        String name           = safeString(cl, arena, device, CL_DEVICE_NAME);
        String vendor         = safeString(cl, arena, device, CL_DEVICE_VENDOR);
        String version        = safeString(cl, arena, device, CL_DEVICE_VERSION);
        String driverVersion  = safeString(cl, arena, device, CL_DRIVER_VERSION);
        String profile        = safeString(cl, arena, device, CL_DEVICE_PROFILE);
        String openclCVersion = safeString(cl, arena, device, CL_DEVICE_OPENCL_C_VERSION);
        String extensions     = safeString(cl, arena, device, CL_DEVICE_EXTENSIONS);

        long deviceType       = safeLong(cl, arena, device, CL_DEVICE_TYPE);
        int  computeUnits     = safeInt (cl, arena, device, CL_DEVICE_MAX_COMPUTE_UNITS);
        long maxWorkGroup     = safeLong(cl, arena, device, CL_DEVICE_MAX_WORK_GROUP_SIZE);
        int  maxClockMHz      = safeInt (cl, arena, device, CL_DEVICE_MAX_CLOCK_FREQUENCY);
        int  addressBits      = safeInt (cl, arena, device, CL_DEVICE_ADDRESS_BITS);
        long globalMem        = safeLong(cl, arena, device, CL_DEVICE_GLOBAL_MEM_SIZE);
        long maxMemAlloc      = safeLong(cl, arena, device, CL_DEVICE_MAX_MEM_ALLOC_SIZE);
        long localMem         = safeLong(cl, arena, device, CL_DEVICE_LOCAL_MEM_SIZE);
        long constantMem      = safeLong(cl, arena, device, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE);
        long globalCache      = safeLong(cl, arena, device, CL_DEVICE_GLOBAL_MEM_CACHE_SIZE);
        long cacheline        = safeLong(cl, arena, device, CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE);
        boolean unifiedMemory = safeInt (cl, arena, device, CL_DEVICE_HOST_UNIFIED_MEMORY) != 0;
        long svmCaps          = safeLong(cl, arena, device, CL_DEVICE_SVM_CAPABILITIES);

        return new DeviceInfo(
                name, vendor, version, driverVersion, profile, openclCVersion,
                deviceType,
                (deviceType & CL_DEVICE_TYPE_GPU_BIT) != 0,
                (deviceType & CL_DEVICE_TYPE_CPU_BIT) != 0,
                computeUnits, maxWorkGroup, maxClockMHz, addressBits,
                globalMem, maxMemAlloc, localMem, constantMem,
                globalCache, cacheline,
                unifiedMemory,
                (svmCaps & CL_DEVICE_SVM_COARSE_GRAIN_BUFFER) != 0,
                (svmCaps & CL_DEVICE_SVM_FINE_GRAIN_BUFFER) != 0,
                extensions);
    }

    private static String safeString(FFMUtil.Library cl, Arena arena,
                                     MemorySegment device, int param) {
        try { return queryDeviceString(cl, arena, device, param); }
        catch (Throwable t) { return "<unknown>"; }
    }

    private static long safeLong(FFMUtil.Library cl, Arena arena,
                                 MemorySegment device, int param) {
        try { return queryDeviceLong(cl, arena, device, param); }
        catch (Throwable t) { return 0L; }
    }

    private static int safeInt(FFMUtil.Library cl, Arena arena,
                               MemorySegment device, int param) {
        try { return queryDeviceInt(cl, arena, device, param); }
        catch (Throwable t) { return 0; }
    }


    // =========================================================================
    // KERNEL ARGUMENTS
    // =========================================================================

    /** Sets an SVM pointer kernel argument. */
    public static void setKernelArgSVM(FFMUtil.Library cl, MemorySegment kernel,
                                       int index, MemorySegment svmPtr) throws Throwable {
        check("clSetKernelArgSVMPointer[" + index + "]",
                (int) cl.invoke("clSetKernelArgSVMPointer", kernel, index, svmPtr));
    }

    /** Sets a cl_mem (address) kernel argument. */
    public static void setKernelArgAddr(FFMUtil.Library cl, Arena arena, MemorySegment kernel,
                                        int index, MemorySegment value) throws Throwable {
        var argBuf = arena.allocate(ValueLayout.ADDRESS);
        argBuf.set(ValueLayout.ADDRESS, 0, value);
        check("clSetKernelArg[" + index + "]",
                (int) cl.invoke("clSetKernelArg", kernel, index,
                        ValueLayout.ADDRESS.byteSize(), argBuf));
    }

    /** Sets a 32-bit integer kernel argument. */
    public static void setKernelArgInt(FFMUtil.Library cl, Arena arena, MemorySegment kernel,
                                       int index, int value) throws Throwable {
        var argBuf = arena.allocate(ValueLayout.JAVA_INT);
        argBuf.set(ValueLayout.JAVA_INT, 0, value);
        check("clSetKernelArg[" + index + "]",
                (int) cl.invoke("clSetKernelArg", kernel, index,
                        (long) Integer.BYTES, argBuf));
    }


    // =========================================================================
    // PROGRAM BUILD LOG
    // =========================================================================

    /**
     * Retrieves the program build log for the device pointed to by {@code devBuf}
     * (a 1-element address buffer). Never throws — returns a descriptive string on failure.
     */
    public static String getBuildLog(FFMUtil.Library cl, Arena arena,
                                     MemorySegment program, MemorySegment devBuf) {
        try {
            MemorySegment dev = devBuf.get(ValueLayout.ADDRESS, 0);
            var sizeBuf = arena.allocate(ValueLayout.JAVA_LONG);
            cl.invoke("clGetProgramBuildInfo", program, dev, CL_PROGRAM_BUILD_LOG,
                    0L, MemorySegment.NULL, sizeBuf);
            long logSize = sizeBuf.get(ValueLayout.JAVA_LONG, 0);
            if (logSize <= 1) return "<empty>";
            var logBuf = arena.allocate(logSize);
            cl.invoke("clGetProgramBuildInfo", program, dev, CL_PROGRAM_BUILD_LOG,
                    logSize, logBuf, MemorySegment.NULL);
            return logBuf.getString(0);
        } catch (Throwable t) {
            return "<failed to retrieve: " + t.getMessage() + ">";
        }
    }


    // =========================================================================
    // CLI — enumerate and display OpenCL devices
    // =========================================================================

    private static final String USAGE = """
            OpenCLUtil — list OpenCL platforms and device capabilities.

            Usage:
              OpenCLUtil [lib=<path>] [header=<path>] [type=gpu|cpu|any] [format=pretty|summary]

            Options:
              lib=<path>        Override libOpenCL.so path (default: auto-detect).
              header=<path>     Override cl.h path (default: /usr/include/CL/cl.h).
              type=gpu|cpu|any  Filter by device type (default: any).
              format=<fmt>      pretty (multi-line) or summary (one-line). Default: pretty.
            """;

    public static void main(String[] args) throws Throwable {
        for (String a : args) {
            if (a.equals("-h") || a.equals("--help") || a.equals("help")) {
                System.out.println(USAGE);
                return;
            }
        }

        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String libPath    = params.stringValue("lib", true);
        String headerPath = params.stringValue("header", true);
        String typeStr    = params.stringValue("type", true);
        String format     = params.stringValue("format", true);

        if (libPath == null)    libPath    = findLibrary();
        if (headerPath == null) headerPath = "/usr/include/CL/cl.h";
        if (format == null)     format     = "pretty";

        long filterType = CL_DEVICE_TYPE_ALL;
        if (typeStr != null) {
            filterType = switch (typeStr.toLowerCase()) {
                case "gpu" -> CL_DEVICE_TYPE_GPU_BIT;
                case "cpu" -> CL_DEVICE_TYPE_CPU_BIT;
                default    -> CL_DEVICE_TYPE_ALL;
            };
        }

        try (FFMUtil.Library cl = FFMUtil.library(libPath)
                .header(headerPath)
                .includePath("/usr/include")
                .load()) {

            Arena arena = cl.arena();

            // --- Enumerate platforms ---
            var numPlatBuf = arena.allocate(ValueLayout.JAVA_INT);
            check("clGetPlatformIDs(count)",
                    (int) cl.invoke("clGetPlatformIDs", 0, MemorySegment.NULL, numPlatBuf));
            int numPlatforms = numPlatBuf.get(ValueLayout.JAVA_INT, 0);
            if (numPlatforms == 0) {
                System.out.println("No OpenCL platforms found.");
                return;
            }
            var platArray = arena.allocate(ValueLayout.ADDRESS, numPlatforms);
            check("clGetPlatformIDs",
                    (int) cl.invoke("clGetPlatformIDs", numPlatforms, platArray, MemorySegment.NULL));

            System.out.println("Found " + numPlatforms + " OpenCL platform(s).");
            int totalDevices = 0;

            for (int p = 0; p < numPlatforms; p++) {
                MemorySegment plat = platArray.getAtIndex(ValueLayout.ADDRESS, p);

                // Count devices of the requested type on this platform
                var numDevBuf = arena.allocate(ValueLayout.JAVA_INT);
                int countErr = (int) cl.invoke("clGetDeviceIDs",
                        plat, filterType, 0, MemorySegment.NULL, numDevBuf);
                if (countErr != CL_SUCCESS) continue;
                int numDevs = numDevBuf.get(ValueLayout.JAVA_INT, 0);
                if (numDevs == 0) continue;

                var devArray = arena.allocate(ValueLayout.ADDRESS, numDevs);
                check("clGetDeviceIDs(platform " + p + ")",
                        (int) cl.invoke("clGetDeviceIDs",
                                plat, filterType, numDevs, devArray, MemorySegment.NULL));

                for (int d = 0; d < numDevs; d++) {
                    MemorySegment device = devArray.getAtIndex(ValueLayout.ADDRESS, d);
                    DeviceInfo info = queryDeviceInfo(cl, arena, device);
                    totalDevices++;

                    System.out.println();
                    System.out.println("=== Platform " + p + ", Device " + d + " ===");
                    System.out.println("summary".equalsIgnoreCase(format)
                            ? info.summary()
                            : info.prettyReport());
                }
            }

            if (totalDevices == 0) {
                System.out.println("No devices matched filter type="
                        + (typeStr == null ? "any" : typeStr));
            } else {
                System.out.println();
                System.out.println("Total devices: " + totalDevices);
            }
        }
    }
}
