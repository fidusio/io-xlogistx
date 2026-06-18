package io.xlogistx.opsec.ssl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Indexed host &rarr; {@link Identity} resolver that replaces the O(N) linear scan
 * with an O(1) exact-name lookup plus a small wildcard pass, while preserving the
 * exact matching semantics and load-order of {@link Identity#matches(String)}.
 *
 * <p>Built once from a fixed identity list and never mutated, so it is safe to
 * publish via a {@code volatile} reference and read lock-free from many handshake
 * threads (mirroring {@link IdentityStore}'s reload-and-swap pattern).</p>
 *
 * <h3>Indexing</h3>
 * <ul>
 *   <li><b>Exact names</b> (SAN dNSName / CN, already lower-cased by
 *       {@link Identity}) go into a {@code HashMap<String,List<Identity>>} &mdash;
 *       <b>O(1)</b> lookup regardless of how many identities are loaded. The list
 *       value supports several identities certifying the same host (e.g. an EC, an
 *       RSA and a PQC cert for one name).</li>
 *   <li><b>Wildcard names</b> ({@code *.foo.com}) go into a small list scanned
 *       linearly only on demand. There are normally very few wildcard certs, and
 *       each test is a couple of string comparisons.</li>
 * </ul>
 *
 * <h3>Wildcard semantics (RFC 6125, single label)</h3>
 * {@code *.foo.com} matches exactly one label deep ({@code a.foo.com}) plus the
 * apex ({@code foo.com}); it does <b>not</b> match {@code a.b.foo.com}. This is the
 * same rule {@link Identity#matches(String)} enforces &mdash; deliberately stricter
 * than a generic suffix/glob matcher, because serving a cert that does not actually
 * cover the SNI host would make the client reject the handshake.
 *
 * <h3>Ordering</h3>
 * Results are returned in the identities' original load order (and de-duplicated),
 * so {@link IdentityKeyManager}'s "first classical the client can verify" style
 * selection is unchanged versus the previous linear scan.
 *
 * <p>JDK 8 compatible.</p>
 */
public final class DomainIdentityMatcher {

    /** A single wildcard ("*.apex") rule bound to its identity and load index. */
    private static final class Wildcard {
        final String suffix; // ".foo.com"
        final String apex;   // "foo.com"
        final int index;     // load-order position of the owning identity
        final Identity id;

        Wildcard(String suffix, String apex, int index, Identity id) {
            this.suffix = suffix;
            this.apex = apex;
            this.index = index;
            this.id = id;
        }

        /** Single-label wildcard test, identical to {@link Identity#matches(String)}. */
        boolean matches(String host) {
            if (host.equals(apex)) {
                return true;
            }
            if (host.endsWith(suffix)) {
                int labelLen = host.length() - suffix.length();
                // exactly one non-empty leftmost label (no embedded dot)
                if (labelLen > 0 && host.lastIndexOf('.', labelLen - 1) < 0) {
                    return true;
                }
            }
            return false;
        }
    }

    private final List<Identity> all;                  // load order, immutable
    private final Map<String, List<Identity>> exact;   // exact host -> identities (load order)
    private final List<Wildcard> wildcards;            // small, load order
    private final Map<Identity, Integer> indexOf;      // identity -> load index (object identity)

    /**
     * Build an index over {@code identities}. The list order is treated as load
     * order and preserved in every result. Identity name lists are taken as-is
     * (already lower-cased by {@link Identity}); an identity with no names is kept
     * in {@link #identities()} but never matched (it is only ever served as the
     * single/default identity).
     */
    public DomainIdentityMatcher(List<Identity> identities) {
        List<Identity> copy = new ArrayList<Identity>(identities);
        Map<String, List<Identity>> ex = new java.util.HashMap<String, List<Identity>>(copy.size() * 2);
        List<Wildcard> wc = new ArrayList<Wildcard>();
        Map<Identity, Integer> idx = new IdentityHashMap<Identity, Integer>(copy.size() * 2);

        for (int i = 0; i < copy.size(); i++) {
            Identity id = copy.get(i);
            idx.put(id, i);
            for (String name : id.names()) {
                if (name == null || name.isEmpty()) {
                    continue;
                }
                if (name.startsWith("*.") && name.length() > 2) {
                    wc.add(new Wildcard(name.substring(1), name.substring(2), i, id));
                } else {
                    List<Identity> bucket = ex.get(name);
                    if (bucket == null) {
                        bucket = new ArrayList<Identity>(2);
                        ex.put(name, bucket);
                    }
                    if (!bucket.contains(id)) {
                        bucket.add(id);
                    }
                }
            }
        }
        this.all = Collections.unmodifiableList(copy);
        this.exact = ex;
        this.wildcards = wc;
        this.indexOf = idx;
    }

    /** All identities, in load order. */
    public List<Identity> identities() {
        return all;
    }

    /** Number of indexed identities. */
    public int size() {
        return all.size();
    }

    /** True if any identity certifies {@code host}. */
    public boolean matches(String host) {
        return resolveFirst(host) != null;
    }

    /**
     * The first identity (lowest load index) certifying {@code host}, or null when
     * none match or {@code host} is null. Equivalent to the first hit of the old
     * linear scan, but without walking non-matching identities.
     */
    public Identity resolveFirst(String host) {
        if (host == null) {
            return null;
        }
        String h = host.toLowerCase(Locale.ROOT);
        Identity best = null;
        int bestIdx = Integer.MAX_VALUE;

        List<Identity> hit = exact.get(h);
        if (hit != null) {
            for (int i = 0; i < hit.size(); i++) {
                int at = indexOf.get(hit.get(i));
                if (at < bestIdx) {
                    bestIdx = at;
                    best = hit.get(i);
                }
            }
        }
        for (int i = 0; i < wildcards.size(); i++) {
            Wildcard w = wildcards.get(i);
            if (w.index < bestIdx && w.matches(h)) {
                bestIdx = w.index;
                best = w.id;
            }
        }
        return best;
    }

    /**
     * All identities certifying {@code host}, in load order and de-duplicated.
     * Empty when none match or {@code host} is null. Used by
     * {@link IdentityKeyManager} to choose among same-host identities by the
     * client's advertised signature algorithms.
     */
    public List<Identity> resolveAll(String host) {
        if (host == null) {
            return Collections.emptyList();
        }
        String h = host.toLowerCase(Locale.ROOT);
        // TreeMap keyed by load index dedups (same identity via exact + wildcard)
        // and yields load order in one pass.
        TreeMap<Integer, Identity> ordered = new TreeMap<Integer, Identity>();

        List<Identity> hit = exact.get(h);
        if (hit != null) {
            for (int i = 0; i < hit.size(); i++) {
                ordered.put(indexOf.get(hit.get(i)), hit.get(i));
            }
        }
        for (int i = 0; i < wildcards.size(); i++) {
            Wildcard w = wildcards.get(i);
            if (w.matches(h)) {
                ordered.put(w.index, w.id);
            }
        }
        if (ordered.isEmpty()) {
            return Collections.emptyList();
        }
        return new ArrayList<Identity>(ordered.values());
    }
}
