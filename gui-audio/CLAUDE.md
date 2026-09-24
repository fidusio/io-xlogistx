# Claude Code Instructions for gui-audio

Swing GUI widgets and (eventually) audio utilities for the io-xlogistx projects.
Java package: `io.xlogistx.gui` (see `package-info.java` for the class map).

## Architecture

The package has these groups:

1. **Icons & helpers**
   - `IconUtil` — the icon library. All icons are SVG-based (`PlusIcon`, `MinusIcon`,
     `CancelIcon`, `SaveIcon`, `UpdateIcon`, `EditIcon`, `DeleteIcon`, `BackIcon`,
     `NextIcon`, `RollbackIcon`, `VisibleIcon`, `InvisibleIcon`, `CopyIcon`, `SearchIcon`,
     `RefreshIcon`, `InfoIcon`, `RunIcon`, `StopIcon`, `PauseIcon`, `CheckIcon`, `AlertIcon`,
     `ErrorIcon`, `QuestionIcon`, `FileIcon`, `FolderIcon`, `UndoIcon`, `RedoIcon`, `PrintIcon`,
     `PanIcon`, `SelectIcon`, `InsertIcon`,
     generic `SVGIcon` + `svgIcon(...)` factories). All extend `IconWidget`; the SVG-based
     ones share the `SVGIconWidget` base. **SVG icon constructor contract**:
     `XxxIcon(int size)` renders the svg with its own colors and does NOT touch the host
     component's background; `XxxIcon(int size, Color color)` tints the glyph and paints
     the icon's background color on the host component.
   - `GUIUtil` — static helpers only: `iconButton(...)` factories, screen capture
     (`captureSelectedArea()`), clipboard, panels/scroll panes, color interpolation
     (`colorToRatio`, `interpolateColors`).
   - `SelectionWindow` — translucent drag-selection overlay covering one monitor;
     `GUIUtil.captureSelectedArea()` shows one per monitor (Lock/Condition handshake,
     predicate-loop over all overlays). Per-display windows, NOT one spanning window:
     macOS "Displays have separate Spaces" clips a spanning window to a single display.
   - Screen capture data: `CaptureArea` (named screen rectangle; owns its lazily
     created capture `Robot`, bound to a `GraphicsDevice` auto-resolved from the
     rectangle by `setCaptureArea(...)` via `GUIUtil.deviceForArea(...)` —
     `setGraphicsDevice(...)` overrides; the area, not the set, carries the device;
     `takeSnapShot(...)` captures itself and serializes concurrent captures on its
     robot), `CaptureAreaSet` (ordered set of areas; `takeSnapShots()` captures
     every area on demand in one sweep — skips null/empty rectangles, snapshots
     carry a UUID id, the area name as source id, and a set-lifetime sequence
     number), `SnapShot` (immutable captured image + id/sourceID/sequence/
     timestamp).
2. **Status displays** — `StatusWidget<M>` base (status tag → mapped display value) with
   `LedWidget` (Color) and `IconStatusWidget` (ImageIcon); `ProgressBarWidget` (percent bar
   colored via `GUIUtil.colorToRatio`).
3. **Data editors** — per-NV-type widgets (`BooleanWidget`, `LongWidget`, `DecimalWidget`,
   `EnumWidget`, `StringWidget`) registered in the `MetaToWidget` singleton, composed into
   forms by `NVGenericMapWidget`; list/tree editors `DynamicComboBox`, `TreeTextWidget`.

### The MetaToWidget binding pattern (important)

`MetaToWidget.SINGLETON.create(gnv)` returns a `MappedObject(nv, widget, Setter)`:
- `valueToMap()` = model → UI, `mapToValue()` = UI → model.
- New NV types are supported by registering a widget factory AND a `Setter` in
  `MetaToWidget.init()` — both registries must be updated together.
- Unregistered NV types intentionally fall back to a **read-only** text field
  (no exception) so `NVGenericMapWidget` can always render a form.
- Save-side validation throws from `mapToValue` (e.g. NVInt int-range check);
  `NVGenericMapWidget.onSave` catches `Exception` and shows an error dialog.

### Viewers and converters

- `MDViewerPanel` — read-only GFM markdown viewer (commonmark → HTML → `JEditorPane`).
  Extensions: tables, strikethrough, task list items.
- `MDToPDF` — static markdown → PDF converter: commonmark (the **same three extensions**
  as `MDViewerPanel`) → HTML → Jsoup DOM → OpenHTMLtoPDF → PDFBox. Embeds the Roboto TTFs
  shipped by `flatlaf-fonts-roboto` (font family `Roboto`, silent fallback to the built-in
  fonts if the jar is absent) so non-Latin-1 text renders. Task-list
  `<input type=checkbox>` is replaced by `[x]`/`[ ]` text (the PDF renderer draws no form
  controls). `DEFAULT_CSS` is public; a caller-supplied stylesheet **replaces** it entirely
  (include `@page`). CLI: `MDToPDF md=in.md [pdf=out.pdf] [css=style.css]` (`ParamUtil`
  `name=value` args).
- `PDFViewerPanel` — PDFBox-backed Swing viewer (details below).

#### PDFViewerPanel

**Rendering.** Pages stack vertically in the panel's own scroll pane (do not wrap it in
another). Only pages within one viewport height of the view are rasterized
(`PDFRenderer.renderImageWithDPI`, dpi = 72 × zoom × device scale) on **one shared daemon
thread** (`RENDER_EXECUTOR`) and kept in a byte-bounded LRU (`DEFAULT_CACHE_BYTES` 64 MB,
`setCacheBytes`, `getPageImage`). A `generation` counter invalidates in-flight renders on
zoom change/close. Every `PDDocument` access is under `docLock` (PDFBox documents are not
thread-safe); the only lock-free reader is painting, which peeks at the volatile
`pageTexts`.

**Layout/zoom.** `layoutPages()` positions the stack with `doLayout` (works without a
peer, so headless tests see real bounds) and then validates for the on-screen case.
`applyZoom` anchors on a page-relative point in points, never on raw stack pixels, because
the fixed gaps between pages do not scale. Zoom modes `CUSTOM`/`FIT_WIDTH`/`FIT_PAGE`
(fit modes re-apply on viewport resize); `zoomTo(page, ptRect)` fits a page area
(e.g. a search `Match`).

**Lifecycle.** `setPDF(bytes|File|InputStream)` parses off the EDT via `BackgroundTask`;
`setDocument(doc, owns)` is synchronous; both go through `install(doc, owns, file)`.
`close()` is idempotent, clears highlights/selection, and the panel is reusable. Page
indexes are **zero-based** in the API, one-based in the toolbar.

**Text.** `PageText` (per page, extracted lazily by a `PDFTextStripper` subclass) keeps
the original-case `text`, a char-by-char lowercased `lower` copy for search (offsets stay
aligned) and one `TextPosition` per char (null for inserted word/line separators). From
it: `search(text)` → `Match`es (page, char range, glyph rects in pt with top-left origin,
one per line); `find(text)` → pages; `setHighlights`/`gotoMatch`/`nextMatch`/
`previousMatch` paint and step (wrapping); `highlightAsync` = search off the EDT +
highlight. Text selection is a page+char-offset range (`select`, `selectAll`,
`getSelectedText` — pages joined by a blank line —, `copySelection`, `clearSelection`,
`charIndexAt(page, xPt, yPt)` hit test over lazily built lines). Selected pages whose text
is not extracted yet request extraction on the render thread and repaint.

**Tools/input.** `Tool` (toolbar toggle group) decides what a plain left drag does:
`PAN` scrolls, `SELECT_TEXT` selects (double click = word, right click = Copy/Select all/
Clear menu), `ZOOM_TO_SELECTION` rubber-bands a rectangle that is fitted to the viewport
(`zoomToViewRect`); Shift+drag rubber-bands with any tool, a plain click in that tool
zooms one step at the pointer. Keys (WHEN_ANCESTOR bindings on the panel, so they also
work with focus in the toolbar fields): PgUp/PgDn scroll a screen (`scrollBy`),
Ctrl+PgUp/PgDn jump pages, Ctrl+Home/End first/last page, Ctrl +/−, Ctrl+0 fit width,
Ctrl+A/Ctrl+C select all/copy, Esc clears the selection else returns to `PAN`; Ctrl+wheel
zooms around the pointer.

**File/print.** Open (`openFile()` → shared `JFileChooser` *.pdf → `setPDF(File)`;
`getFile()` remembers the origin, null for byte/stream documents). Save (`saveAs()`,
`save(File)`: `PDDocument.save` to a temp file off the EDT, then moved into place; saving
**over the source file** closes, replaces and reloads the document because PDFBox reads
lazily from the source — never `save` straight onto it). Print (`print()`: `PrinterJob`
dialog on the EDT, `job.print()` off the EDT; `createPageable()` wraps PDFBox
`PDFPageable` so every page prints under `docLock`; it is a snapshot guarded by the
`edits` counter, so after `close()` or any insert/delete it reports `NO_SUCH_PAGE` — hosts
create a fresh one after edits). Insert (`insertDialog()` → file chooser accepting `*.pdf` **and** `*.md`
(Markdown is converted with `MDToPDF` first) + position dialog; `insertPDF(file, index)`
async, `insertDocument(doc, index)` sync primitive; index 0 = beginning, page count = end,
n = after page n. `mergeInto` = `PDFMergerUtility.appendDocument` (deep copy, source may
be closed) then `PDPageTree.remove` + `insertBefore` to move the appended pages into
place; `refreshPages` rebuilds the page views keeping document/zoom/tool and clears
highlights + selection). Merging sets `isModified()`; `save` clears it; `openFile()` and
hosts' window-closing call `confirmDiscard()`. No undo — reopen the file instead.
Delete (`deleteDialog()` → one text field, pre-filled with the current page, accepting
`current` / `cur` / `this`, single pages, ranges `a-b` (`b-a` flipped) and comma / semicolon /
space separated lists of those, one-based as the toolbar shows pages; an unusable entry is
reported and the dialog re-shown; `deletePages(String)` parses via the public static
`parsePageSelection(text, currentPage, pageCount)` and calls the primitive
`deletePages(int[])` — zero-based, any order, duplicates ignored, synchronous under `docLock`
(`PDDocument.removePage` highest index first), then `refreshPages` shows the page that took
the first deleted page's slot, or the last page). Out-of-range indexes and a selection that
would empty the document throw `IllegalArgumentException` with a dialog-ready message and
change nothing. Deleting sets `isModified()` like Insert; the Delete button is enabled only
with two or more pages. Same no-undo rule as Insert.

**Toolbar order.** Open, Save, Print, Insert, Delete | Pan, Select text, Zoom to selection, Copy | prev,
page field / count, next | zoom out, zoom combo (presets + fit modes), zoom in | search
field, find next, "n / m". Annotations and form editing are intentionally out of scope.

### Hex editor (`io.xlogistx.gui.hexeditor`)

- `HexEditor` — pure model over zoxweb `UByteArrayOutputStream` (no Swing): file
  I/O, edits, search/replace, undo/redo (bounded 100). Undo entry types MODIFY /
  INSERT / DELETE / REPLACE — length-changing replaces MUST use REPLACE (MODIFY
  undo corrupts the buffer). `reset()` = new-document (non-undoable) vs `clear()`
  (undoable edit).
- `HexPanel` — embeddable Swing view (offset/hex/ASCII columns, nibble-level
  editing, clip-aware painting). Caret blink timer is started/stopped in
  `addNotify`/`removeNotify`.
- `HexEditorPane` — **the embeddable component** (JPanel: toolbar of icon-only
  `IconUtil` buttons with tooltips + view + status
  bar + all dialogs, parented to the pane). Hosts install `createMenuBar()` in
  their own window; document state via `getDocumentTitle()`/`isModified()`/
  change listeners; `confirmDiscard()` before closing. Never exits the JVM.
- `HexEditorFrame` — thin standalone wrapper; `System.exit` only when
  `setExitOnClose(true)` (set by its `main`), so opening the frame from a host
  app is safe.
- `HexEditorConsole` — interactive CLI over the same model.

## Rules / invariants (do NOT regress)

- **EDT discipline**: `GUIUtil.captureSelectedArea()` must be called OFF the EDT (it blocks
  and throws `IllegalStateException` on the EDT); it realizes the `SelectionWindow` on the
  EDT via `invokeAndWait` and disposes it via `invokeLater`. Keep it that way.
- **No GUI work in static initializers** — no `Toolkit`/`UIManager` calls at class-init
  (breaks headless use and look-and-feel ordering). L&F icons are exposed lazily via
  `IconUtil.plusIcon()` / `minusIcon()`.
- **DecimalWidget formats with `Locale.US` symbols** — its `DocumentFilter` validates via
  `Double.parseDouble`, so the display format must use `.` regardless of default locale.
- **SVGIcon caches** — parsed `SVGDocument`s are cached per resource URL
  (`SVG_DOC_CACHE`) and each icon caches its raster per device scale. Don't re-render per
  paint.
- **macOS color swap** in `IconWidget`: glyph/background colors are swapped on macOS
  (Swing buttons there don't honor background the same way). Null defaults are applied
  BEFORE the swap so neither field can end up null.
- SVG resources live in `src/main/resources/io/xlogistx/gui/icons/` (`plus`, `minus`,
  `cancel`, `edit`, `delete`, `back`, `next`, `rollback`, `visible`, `invisible`, `save`,
  `update`, `copy`, `search`, `refresh`, `info`, `run`, `stop`, `pause`, `check`, `alert`,
  `error`, `question`, `file`, `folder`, `undo`, `redo`, `print`, `pan`, `select`, `insert`). All are Feather-style: 24x24 viewBox,
  `fill="none"`, `stroke="#5A5A5A"`, stroke-width 2, round caps/joins — match this style
  when adding new ones. Each `XxxIcon` class maps to the same-named svg
  (`PlusIcon`→`plus.svg`, ...), except: `EditIcon`→`edit.svg` is a pencil,
  `DeleteIcon`→`delete.svg` is a trash can, `UpdateIcon`→`update.svg` is two chasing
  arrows (sync), `RefreshIcon`→`refresh.svg` is a single clockwise arrow,
  `RollbackIcon`→`rollback.svg` is its counterclockwise mirror, `RunIcon`→`run.svg` is a
  play triangle, `InfoIcon`→`info.svg` is an "i" in a circle. `UndoIcon`/`RedoIcon` are
  hook arrows and are deliberately NOT mirrors of `rollback`/`refresh` (those two are
  already exact mirrors of each other and read as revert/reload, not undo/redo).
  `CheckIcon`/`AlertIcon`/`ErrorIcon`/`QuestionIcon` are the intended status glyphs for
  `IconStatusWidget`; `ErrorIcon` (x-in-circle) is distinct from `CancelIcon` (bare x,
  a dismiss action), and `CheckIcon` (bare tick, "ok") from `SaveIcon` (floppy disk,
  "write to disk"). **No two svgs may render the same glyph** — the only 100% matches
  allowed in the set are the three intentional h-mirror pairs `back`/`next`,
  `undo`/`redo` and `rollback`/`refresh`. Every svg has a
  dedicated class; one-off svgs can be loaded via `IconUtil.svgIcon(...)`.

## Dependencies

- **JSVG** (`com.github.weisj:jsvg`) — SVG rendering. Do not add batik or other SVG libs.
- **commonmark** (`org.commonmark` + gfm-tables/gfm-strikethrough/task-list-items
  extensions) — Markdown parsing/rendering for `MDViewerPanel` and `MDToPDF`. Do not add
  flexmark or other Markdown libs.
- **OpenHTMLtoPDF** (`io.github.openhtmltopdf:openhtmltopdf-pdfbox`, version from the
  external parent pom `xlogistx-mvn`) + **Jsoup** — HTML → PDF for `MDToPDF`.
- **PDFBox** (`org.apache.pdfbox:pdfbox`, `pdfbox.version` in the io-xlogistx root pom;
  must stay on the line OpenHTMLtoPDF is built against, currently 3.0.x) — page
  rendering/text extraction for `PDFViewerPanel`. Do not add ICEpdf/JPedal/other PDF
  libs; `PDFViewerPanel` is the viewer.
- `common` module (`NVColor`), zoxweb (`NVGenericMap`, `MappedObject`, `SUS`, `ServerUtil`).

## Demos / manual testing

Interactive demos (main methods) in `src/test/java/io/xlogistx/gui/test/`:
- `IconWidgetDemo` — all icons as labels and buttons
- `StateIconDemo` — status widgets
- `CaptureSelectedAreaDemo` — screen-area selection + screenshot (shows the intended
  off-EDT usage of `captureSelectedArea()`)
- `CaptureAreaSetDemo` — build a `CaptureAreaSet` interactively (add/name/remove
  areas), snap selected areas or all via `takeSnapShots(...)`, shows the latest snapshot
- `MDViewerDemo` — live markdown editor (left), rendered `MDViewerPanel` (middle) and
  `PDFViewerPanel` showing the `MDToPDF` output (right, regenerated off the EDT 500 ms
  after the last keystroke, current page preserved)
- `PDFViewerDemo` — standalone `PDFViewerPanel` window; `PDFViewerDemo [file.pdf]`,
  without an argument it shows a generated multi-page sample (use the Open button)
- `MDViewerOverrideCheck` — windowless assertion run for
  `MDViewerPanel.overrideScrollPane(...)`; exits 0 on success

Build: `mvn clean install -pl gui-audio -am` (from repo root).

Headless-safe JUnit tests (`src/test/java/io/xlogistx/gui/`): `MDToPDFTest` and
`PDFViewerPanelTest` (sets `java.awt.headless=true`, lays the component tree out by hand
because `validate()` needs a peer, drives the panel through `invokeAndWait`). The other
Swing classes are verified via the demos only. `mvn test` skips tests in this build (parent
`skipTests`); see the memory note on the CLI JUnit launcher recipe.

## Known limitations (accepted, not bugs)

- Multi-monitor selection uses one `SelectionWindow` per display; the selection
  rectangle is returned in virtual-screen coordinates (origin can be negative when
  a monitor sits left of/above the primary) and cannot cross monitors — it clips
  at the edge of the display the drag started on. Resolve the monitor a selection
  landed on via `GUIUtil.deviceForArea(Rectangle)`.
- macOS: `Robot.createScreenCapture` needs the Screen Recording permission
  (System Settings → Privacy & Security); without it captures silently show only
  the wallpaper — no exception is thrown.
- No ESC/cancel for a selection in progress (a JWindow without a visible owner cannot get
  key focus; would need an AWTEventListener if ever required).
- A click without drag yields an empty (0x0) selection rectangle — callers must handle it
  (see `CaptureSelectedAreaDemo`).
- `paintIcon` implementations call `c.setBackground(...)` — required by the macOS swap
  behavior; only effective on opaque components.
