package io.xlogistx.s2t.platform;

import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.platform.windows.WindowsX64Platform;

import java.util.Locale;

/**
 * Selects the {@link NativePlatform} for the running JVM.
 * <p>
 * This is the only place that knows which platforms exist. Today that is Windows
 * x86-64; macOS and Linux are recognized and reported as not built yet, so the error
 * names the platform instead of failing later inside a library load.
 */
public final class NativePlatforms {

    /** What the error message lists. Extend when a platform is added. */
    private static final String SUPPORTED = "Windows x86-64";

    private NativePlatforms() {
    }

    /**
     * @throws S2TException on a platform with no packaged native library
     */
    public static NativePlatform current() throws S2TException {
        return forOs(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    /**
     * The pure half of {@link #current()}, so the mapping can be tested on any machine.
     * <p>
     * Order matters, for the same reason as in {@code xlogistx-net}'s
     * {@code PcapPlatform.forOsName}: mac/darwin is tested BEFORE windows and windows
     * is matched on the whole word, because {@code "darwin".contains("win")} is true.
     */
    public static NativePlatform forOs(String osName, String osArch) throws S2TException {
        String os = osName == null ? "" : osName.toLowerCase(Locale.ROOT);
        String arch = normalizeArch(osArch);

        if (os.contains("mac") || os.contains("darwin")) {
            throw notBuilt("macOS", arch, osName, osArch);
        }
        if (os.contains("windows")) {
            if ("x86_64".equals(arch)) {
                return WindowsX64Platform.INSTANCE;
            }
            throw notBuilt("Windows", arch, osName, osArch);
        }
        if (os.contains("linux")) {
            throw notBuilt("Linux", arch, osName, osArch);
        }
        throw new S2TException("Speech-to-text has no native library for os.name='" + osName
                + "', os.arch='" + osArch + "'. Supported: " + SUPPORTED + ".");
    }

    /** {@code amd64} and {@code x86_64} are the same thing, as are {@code arm64} and {@code aarch64}. */
    static String normalizeArch(String osArch) {
        String arch = osArch == null ? "" : osArch.toLowerCase(Locale.ROOT);
        return switch (arch) {
            case "amd64", "x86_64", "x64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> arch;
        };
    }

    private static S2TException notBuilt(String family, String arch, String osName, String osArch) {
        return new S2TException("Speech-to-text is not built for " + family + " " + arch
                + " yet (os.name='" + osName + "', os.arch='" + osArch + "'). Supported: "
                + SUPPORTED + ".");
    }
}
