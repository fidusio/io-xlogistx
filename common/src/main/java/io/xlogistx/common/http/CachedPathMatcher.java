package io.xlogistx.common.http;


import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.RegistrarMapDefault;

import java.io.IOException;
import java.nio.file.Path;

public class CachedPathMatcher {

    public static final LogWrapper log = new LogWrapper(CachedPathMatcher.class).setEnabled(true);
    private final RegistrarMapDefault<String, Path> cachedMatches;// = (RegistrarMapDefault<String, Path>) new RegistrarMapDefault<String, Path>().setKeyFilter(DataEncoder.StringUpper);


    public CachedPathMatcher() {
        this(null);
    }

    public CachedPathMatcher(RegistrarMapDefault<String, Path> cache) {
        cachedMatches = cache != null ? cache : (RegistrarMapDefault<String, Path>) new RegistrarMapDefault<String, Path>().setKeyFilter(DataEncoder.StringLower);
    }


    public Path findIn(Path base, String subPath) throws IOException {
//        Path searchPathObj = Paths.get(subPath);
//        if(log.isEnabled()) log.getLogger().info("");
//        Path match = cachedMatches.lookup(subPath);
//        if(log.isEnabled()) log.getLogger().info(subPath + " from base " + base);
//        if(match == null) {
//            try (Stream<Path> stream = Files.walk(base)) {
//                Optional<Path> search = stream
//                        .filter(IOUtil::isRegularFile)
//                        .filter(p -> endsWithIgnoreCase(p, searchPathObj))
//                        .findFirst();
//
//                if(log.isEnabled()) log.getLogger().info("match" + match + " " + search);
//
//                if (search.isPresent()) {
//
//                    match = search.get();
//                    cachedMatches.map(match, subPath);
//                    if(log.isEnabled()) log.getLogger().info("Found added to cache");
//                }
//            }
//        }
//
//        return match;
        return IOUtil.findFirstMatchingInPath(base, subPath, cachedMatches);
    }


    /**
     * Optional: clear cache externally if needed
     */
    public synchronized void clearCache() {
        cachedMatches.clear(true);
    }
}
