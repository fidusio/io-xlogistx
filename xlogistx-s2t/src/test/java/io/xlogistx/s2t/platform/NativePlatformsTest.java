package io.xlogistx.s2t.platform;

import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.platform.windows.WindowsX64Platform;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Platform selection is pure string logic, so every platform is tested on any machine. */
class NativePlatformsTest {

    @ParameterizedTest
    @CsvSource({
            "Windows 10,  amd64",
            "Windows 11,  amd64",
            "Windows 11,  x86_64",
            "Windows Server 2022, AMD64"
    })
    void windowsOnIntelSelectsTheWindowsPlatform(String osName, String osArch) throws S2TException {
        assertSame(WindowsX64Platform.INSTANCE, NativePlatforms.forOs(osName, osArch));
    }

    @ParameterizedTest
    @CsvSource({
            "Mac OS X,   aarch64, macOS",
            "Mac OS X,   x86_64,  macOS",
            "Darwin,     arm64,   macOS",
            "Linux,      amd64,   Linux",
            "Linux,      aarch64, Linux",
            "Windows 11, aarch64, Windows"
    })
    void platformsNotBuiltYetAreNamedInTheError(String osName, String osArch, String family) {
        S2TException e = assertThrows(S2TException.class, () -> NativePlatforms.forOs(osName, osArch));
        assertTrue(e.getMessage().contains("not built for " + family), e.getMessage());
        assertTrue(e.getMessage().contains("Windows x86-64"), e.getMessage());
    }

    /** "darwin" contains "win": it must never be routed to the Windows platform. */
    @Test
    void darwinIsNotMistakenForWindows() {
        S2TException e = assertThrows(S2TException.class, () -> NativePlatforms.forOs("Darwin", "x86_64"));
        assertTrue(e.getMessage().contains("macOS"), e.getMessage());
    }

    @Test
    void unknownOperatingSystemIsRejectedWithItsName() {
        S2TException e = assertThrows(S2TException.class, () -> NativePlatforms.forOs("SunOS", "sparcv9"));
        assertTrue(e.getMessage().contains("SunOS"), e.getMessage());
        assertThrows(S2TException.class, () -> NativePlatforms.forOs(null, null));
    }

    @Test
    void architectureAliasesAreNormalized() {
        assertEquals("x86_64", NativePlatforms.normalizeArch("amd64"));
        assertEquals("x86_64", NativePlatforms.normalizeArch("AMD64"));
        assertEquals("aarch64", NativePlatforms.normalizeArch("arm64"));
        assertEquals("riscv64", NativePlatforms.normalizeArch("riscv64"));
        assertEquals("", NativePlatforms.normalizeArch(null));
    }

    @Test
    void windowsPlatformListsDependenciesBeforeTheSpeechLibrary() {
        NativePlatform p = WindowsX64Platform.INSTANCE;
        assertEquals("windows-x86_64", p.id());
        assertEquals("native/windows-x86_64", p.resourceDir());
        assertEquals("libwhisper.dll", p.mainLibrary());
        assertEquals("libwinpthread-1.dll", p.libraryFiles().get(0));
    }

    /** The binaries the platform names must really be on the classpath. */
    @Test
    void windowsLibrariesArePackaged() {
        NativePlatform p = WindowsX64Platform.INSTANCE;
        for (String file : p.libraryFiles()) {
            String resource = "/" + p.resourceDir() + "/" + file;
            assertNotNull(NativePlatformsTest.class.getResource(resource), resource + " is not packaged");
        }
    }
}
