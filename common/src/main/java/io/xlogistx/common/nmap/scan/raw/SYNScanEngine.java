package io.xlogistx.common.nmap.scan.raw;

import io.xlogistx.common.nmap.scan.ScanType;

/**
 * TCP SYN (half-open) scan engine.
 * Delegates to nmap -sS which requires root/admin privileges.
 */
public class SYNScanEngine extends RawScanEngine {

    @Override
    public ScanType getScanType() {
        return ScanType.SYN;
    }

    @Override
    public String getDescription() {
        return "TCP SYN Scan - Half-open scanning (requires privileges)";
    }
}
