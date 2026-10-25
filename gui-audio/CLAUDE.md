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
     `PanIcon`, `SelectIcon`, `AreaIcon`, `InsertIcon`, `PDFIcon`, `CameraIcon`, and the PDF
     editor set added 2026-10-15: `HighlightIcon`, `UnderlineIcon`, `StrikeoutIcon`, `NoteIcon`,
     `PenIcon`, `RectangleIcon`, `EllipseIcon`, `LineIcon`, `ArrowIcon`, `TextBoxIcon`,
     `RotateLeftIcon`, `RotateRightIcon`, `RotateImageLeftIcon`, `RotateImageRightIcon` (framed picture with a curved arrow, 2026-10-16: rotate an image stamp, not a page), `ThumbnailsIcon` (a window with a list strip on the left: the thumbnail sidebar toggle, 2026-10-17), `MoveIcon`, `AnnotSelectIcon`, `FormIcon`,
     `EditTextIcon` (T with a pencil tip: rewrite page text; `textbox.svg` is a T in a box),
     `PictureIcon` (framed landscape with a sun: place an image, 2026-10-15);
     generic `SVGIcon` + `svgIcon(...)` factories). All extend `IconWidget`; the SVG-based
     ones share the `SVGIconWidget` base. **SVG icon constructor contract**:
     `XxxIcon(int size)` renders the svg with its own colors and does NOT touch the host
     component's background; `XxxIcon(int size, Color color)` tints the glyph and paints
     the icon's background color on the host component.
   - `UIFontSize` (2026-10-17) — the control text size as one setting: `apply(size)` scales
     every font the look and feel defines by `size / base` (base = the label size, read on first
     use; originals are kept so `reset()` restores them exactly), refreshes every open window
     (`refresh(root)` for a tree outside a window) and tells `addListener` consumers (components
     that derive their own font re-derive it); `larger()` / `smaller()` step by `STEP`, clamped to
     `MIN`..`MAX`. `FontSizeWidget` is the toolbar control ("Aa" + spinner) that drives and follows
     it; `PDFViewerPanel` puts one at the right end of its toolbar (`getFontSizeWidget()`), the PDF
     editor adds View ▸ Control text size and remembers the value in its settings. The widget's own
     label, spinner and editor field keep the **base** size (2026-10-23, `pinFonts()`: plain
     non-`UIResource` fonts, which `updateComponentTreeUI` leaves alone, re-pinned after each
     change), so the knob does not grow or shrink with the setting it changes.
     **Scoped (2026-10-23):** `apply(root, size)` sizes **one component tree only** — every
     component under `root` gets a plain non-`UIResource` font, its original scaled by
     `size / base`, which the host application's `apply(size)` / `updateComponentTreeUI` leaves
     alone, and nothing outside the tree is touched; the base size restores the originals and
     refreshes, handing the tree back to the look and feel; subtrees carrying the client
     property `PINNED` = `TRUE` are skipped (the widget pins itself); `get(root)` reports the
     scoped size, or the application size the tree follows. `FontSizeWidget(Component scope)` /
     `setScope(scope)` drives that one tree and then ignores the application size.
     `PDFViewerPanel`'s widget is **scoped to the viewer by default** — a viewer embedded in an
     application (no-sneak's PDF dialog) must neither resize the application nor be resized by
     it, which is what the maintainer saw before — and `setFontSizeScope(null)` re-points it at
     the application; `PDFEditorPane` does that, because the editor *is* the application around
     the viewer and its View ▸ Control text size and the spinner must agree.
   - `PDFSecurity` (2026-10-17) — a PDF's password protection as one immutable value: open
     (user) password, owner password (empty = the open one), permission bits (`of(...)`, `NONE`,
     `loaded(doc, password)` reads a just-opened document's permissions, `describe()` for status
     text, `applyTo(doc)` = `protect` with AES-256 or `setAllSecurityToBeRemoved`). **PDFBox
     encrypts streams and strings in memory while it saves**, so `applyTo` goes on a throwaway
     copy, never on the document being shown (see `PDFViewerPanel.writeDocument`).
   - `GUIUtil` — static helpers only: `iconButton(...)` factories, screen capture
     (`captureSelectedArea()`), clipboard, panels/scroll panes, color interpolation
     (`colorToRatio`, `interpolateColors`), `askPassword(parent, title, message)` (2026-10-17: a
     modal `JPasswordField` dialog with the FlatLaf reveal button, null when cancelled or
     headless).
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

### Form and shell primitives (2026-10-24)

Added for no-sneak's UI redesign under the rule *generic widgets live here, application screens
don't*. All Java 8, all colours through `UITokens`, so a FlatLaf theme restyles them at once.

- `UITokens` — the semantic palette and type helpers in one place: `accent()`, `accentSoft()`,
  `accentText()`, `text()`, `muted()`, `border()`, `surface()`, `surfaceAlt()`, `ok()`/`okSoft()`,
  `warn()`/`warnSoft()`, `danger()`/`dangerSoft()`, `neutral()`/`neutralSoft()`. Each asks
  `UIManager` first (`xlogistx.<name>` override, then the look-and-feel key such as
  `Component.accentColor`, `Label.disabledForeground`, `Component.borderColor`) and falls back to
  the design value. `font(style, delta)`, `mono(delta)`, `baseFont()`. `primary(button)` styles the
  one accent-filled action of a view (FlatLaf `STYLE` string), `link(button)` an inline link-like
  button (toolbar type, accent text, hand cursor).
- `BadgeLabel` — pill label with `Tone {OK, WARN, DANGER, NEUTRAL, ACCENT}`, optional icon; text on
  a soft tint at 4.5:1 or better.
- `InlineMessage` — the one-line message under a form: `info` (muted), `ok`, `error` (danger),
  `clear`; always keeps its line so forms do not jump.
- `DirectoryField` — read-only path + **Choose…** over a directories-only chooser shown as a *save*
  dialog (a directory that does not exist yet can be typed). `setDirectory` is silent;
  `onChange` fires on choices made through the button; `startDirectory(Supplier)` for the chooser's
  start.
- `FormPanel` — stacked form (small bold label above the field, optional muted hint below) on
  MigLayout `wrap 1, hidemode 3`. `field` / `requiredField` (red asterisk) / `row(component)`, and
  named **groups**: `group(key, adder)` records every row added inside, `showGroup(key, visible)`
  hides them together without leaving a gap — conditional sections such as first-run rows.
- `StepperPanel` — numbered steps down the page (1-based): `addStep(title, description, body)`,
  `activate`, `complete(index, summary, onChange)` collapses a step to a mono summary line with an
  optional Change button, `reopen`, `setStepEnabled`, `getState` (`TODO`/`ACTIVE`/`DONE`). A rail
  joins the markers; the done marker is a check.
- `SplashSidePanel` — the dark brand half of a sign-in screen: brand line, large wrapping title,
  tagline, check-marked points, muted mono footer. All copy passed in.
- `WrapLabel` — a label that wraps at an explicit width (`setWrapWidth`), its preferred size
  computed by sizing its HTML view to that width. **Why it exists:** Swing has no
  height-for-width, so a wrapping `JTextArea` or a free HTML label in MigLayout reports a height
  for whatever width it was last laid out at — the first cut of `SplashSidePanel` came out with
  rows three times too tall. Containers set the width they have from `doLayout()`
  (`SplashSidePanel`, `StepperPanel` descriptions, `FormPanel` hints do); the width only changes
  when it really changed, so there is no relayout loop.
- `ScrollablePanel` — a `JScrollPane` view that tracks the viewport's width always and its height
  while the content fits, so a layout can centre a card in the free space and the pane scrolls
  only once the window is shorter than the content.
- `SideNavPanel` (Phase 2, same day) — the application's one navigation column, 232 px:
  `section(key, title)` headings, `item(key, icon, label)` flat toggles in one `ButtonGroup`
  (FlatLaf toolbar-button style, accent-soft selection), `footerAction(icon, label, Runnable)` and
  `footer(component)`. It selects, it does not navigate: `onSelect(Consumer<String>)` fires on
  clicks only, `select(key)` highlights without firing, so host navigation and sidebar never loop.
  `setSectionVisible` / `setItemVisible` hide an admin section for non-admins.
- `HeaderBar` — brand, a mono status chip (`setStatus(icon, text)`), the subject
  (`setSubject(name, badge)`: initial avatar, name, optional role badge; `clearSubject()`), and
  right-aligned `addAction(button)`s.
- Navigation icons as plain SVGs for `IconUtil.svgIcon(resource, size, color)` (tinted, no
  class each): `scan`, `clock`, `flask`, `chat`, `list`, `book`, `plug`, `user`, `archive`,
  `help`, `capture`.
- Phase 3 (same day): `ChipPanel` — a wrapping row of removable pills (`setChips`, `onRemove` with
  the chip's key, `addAction` trailing "+ Add …" chip, `setEmptyText`); it shows what it is given
  and never edits its own list. `WrapLayout` under it — a `FlowLayout` whose preferred height
  accounts for wrapping (Rob Camick's fix), because a plain FlowLayout reports one row's height and
  a chip row in a vertical layout gets clipped. `SegmentedControl` — one bar of mutually exclusive
  options (`select` silent, clicks fire `onChange(int)`, `clearSelection` is a valid "none of
  these"). `KeyValuePanel` — muted key / wrapping value grid for detail panes (`put`, `putMono`,
  `clear`). `Tables.style(JTable)` — the house table look (32 px rows, no grid, quiet bold header,
  accent-soft selection, sorter on) and `Tables.width(table, column, px)`.
- Icons: `KeyIcon`, `LockIcon`, `LogoutIcon`, `ShieldIcon` (`key.svg`, `lock.svg`, `logout.svg`,
  `shield.svg`), same two-constructor contract as the rest.

`PagePanel` (Phase 5, same day) is the frame every application page shares: a title and a
one-line description over `UITokens.ground()`, an optional `action(component)` at the right of
the title, and white bordered `card(content)`s below (the last one takes the remaining height;
`row(component)` for a toolbar between). `UITokens.ground()` is the page background token;
`UITokens.mono(delta)` takes its family from `UIManager "xlogistx.monoFamily"` when an
application sets one (a bundled JetBrains Mono), else the logical `MONOSPACED`.

`CardStack` (Phase 4, same day) reports the **visible** card's preferred and minimum size, not a
plain `CardLayout`'s maximum over every card: a stack in a scroll pane used to be as tall as its
tallest hidden card, so a small placeholder card sat below the fold with a scrollbar beside it. In
a `BorderLayout` centre nothing changes. A third MigLayout lesson from the same page: a card whose
preferred height is its tallest content needs `hmin 0` or the page keeps that height and overflows
the window.

Two MigLayout lessons paid for on 2026-10-24: a grid needs `wrap N` in the layout constraints or
every `add` lands in one row (the stepper's header and form were side by side, off the card); and
`hidemode 3` removes a hidden component's *cell* too, so a component that must keep its column
(the stepper's last rail) stays visible and just paints nothing. A `CardLayout` keeps the tallest
card's height — the stepper toggles body/summary visibility instead. Before handing a screen
over, paint it headless to a PNG and look at it: tests do not see layout.

Tests: `FormPanelTest` (headless: a group hides exactly its rows, the required mark and
`labelFor`, the inline message keeps its line, stepper states through activate / complete /
reopen, badge tones, token fallbacks). Visual: `test/StepperPanelDemo` puts them together as a
two-step unlock card beside a splash panel.

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
- `MermaidRenderer` — pure Java renderer for the Mermaid **flowchart** subset (no
  browser/JS/network); details below. `MDToPDF` turns ```` ```mermaid ```` blocks into
  `<p class="diagram"><img data:png>` at scale 2, capped at `DIAGRAM_MAX_WIDTH` CSS px;
  unsupported diagrams (sequence, class, ...) stay code blocks. `MDViewerPanel` still shows
  the source (Swing's HTML kit has no data-URI images).
- `PDFViewerPanel` — PDFBox-backed Swing viewer (details below). Its tool strategy API
  (`PDFToolHandler`, `PDFToolContext`, built-ins in package-private `PDFToolHandlers`) and
  edit hooks (`PDFViewerPanel.EditDelegate` + direct page primitives) are what the PDF
  editor in `apps` (`io.xlogistx.editor.pdf`, design in `PDF-EDIT-DESIGN.md`) builds on.
- `io.xlogistx.gui.pdf.PageTransform` — pure-Java PDF user space ↔ view space (points,
  top-left origin of the displayed page: crop box + rotation applied) conversion; the one
  place that math lives (`PageView` sizes, link rectangles, future annotation geometry).
- `PDFViewerApp` — standalone application (main class) around `PDFViewerPanel`:
  `PDFViewerApp [file.pdf | file.md | image.png]`, starts empty without an argument; title
  follows file/page/modified state, window close goes through `confirmDiscard()` then exits
  the JVM. Window icon = `IconUtil.windowIcons(IconUtil.PDFIcon::new, Color.WHITE,
  NVColor.BOOTSTRAP_RED.getValue())` — the badge form, because the thin grey outline is an
  unreadable smudge at the 16 px Windows title bar renders.
  The test-side `PDFViewerDemo` is the same window pre-loaded with a generated sample.

#### MermaidRenderer

**Pipeline.** `isFlowchart` (cheap header check) → `parse` → `Graph` of `Node`s and
`Edge`s → `render(graph, scale)` (layout + Java2D paint) → `renderPNG`. Anything the
parser does not understand throws `IllegalArgumentException` so callers can fall back to
the source text.

**Syntax.** Header `flowchart`/`graph` + `TD|TB|BT|LR|RL`. Ten node shapes by bracket
pair (`[]` rect, `()` round, `([])` stadium, `[[]]` subroutine, `[()]` cylinder, `(())`
circle, `{}` diamond, `{{}}` hexagon, `[//]`/`[\\]` parallelogram, `>]` flag), matched
longest-opener-first via `OPENERS`. Labels: optional quotes, `<br/>` → newline, other tags
stripped, basic entities decoded. Edges `-->`, `---`, `-.->`, `-.-`, `==>`, `===`
(`x`/`o` heads count as arrows), labels as `-->|t|` or `-- t -->`, chains, `&` fans.
Statements split on newlines and top-level `;`, `%%` comments dropped. `subgraph`/`end`,
`classDef`, `class`, `style`, `linkStyle`, `click`, `direction` lines are skipped (nodes
inside subgraphs are drawn ungrouped). Ids are `[A-Za-z0-9_]+` — never allow `-` or the
scanner would eat `-->`.

**Layout (Sugiyama-lite, `layout()`).** Sizes from `FontMetrics` (labels wider than
`MAX_LABEL_WIDTH` are word-wrapped first, like Mermaid). DFS marks back edges; layers by
longest path over forward edges; four barycenter sweeps order each layer; then 12
relaxation rounds move every node to the mean of **all** its neighbours (both directions)
and `resolveOverlaps` pushes layer neighbours apart symmetrically — this is what centres
parents over children and spreads siblings evenly (one-directional placement drifted
everything right). Work is done on a main/cross axis pair and mapped to x/y at the end
(`vertical`, `reversed` for BT/RL).

**Painting.** Neutral grey theme like the Claude app's Mermaid output (`NODE_FILL`
#EDEDEA, `NODE_STROKE` #D2D2CD, `EDGE` #9A9A9A, text #333), not Mermaid's lavender
default — change these constants for another look (`MermaidRendererTest` counts
`NODE_FILL` pixels, keep it in sync). Forward edges are cubics from
`anchorToward` (where the centre-to-centre line crosses the box, so fans leave a node at
different points) with tangents along the layer axis; same-layer edges are straight; back
edges leave the near side, enter the far side and loop past the farthest node of the layers
they span (`BACK_EDGE_ROOM` is reserved in the image). Arrowheads are filled triangles at
t=1, labels sit at t=0.5 on a `#E8E8E8` pill.

**Verifying changes.** Tests check parsing, layering, non-overlap, pixels and PNG output,
not looks: render the three diagrams in `MermaidRendererTest` to PNG and eyeball them
against Mermaid/Claude output (the scratch `RenderSamples` recipe: write PNGs via
`renderPNG` and open them).

#### PDFViewerPanel

**Rendering.** Pages stack vertically in the panel's own scroll pane (do not wrap it in
another). Only pages within one viewport height of the view are rasterized
(`PDFRenderer.renderImageWithDPI`, dpi = 72 × zoom × device scale) on **one shared daemon
thread** (`RENDER_EXECUTOR`) and kept in a byte-bounded LRU (`DEFAULT_CACHE_BYTES` 64 MB,
`setCacheBytes`, `getPageImage`). A `generation` counter invalidates in-flight renders on
zoom change/close; per page, `PageView.contentVersion` (bumped by `invalidatePage(page)`,
stored in the cache entry and captured by `requestRender`) drops one page's raster and
cached links after an in-place content change (annotations) without touching the others;
`invalidatePage` also calls `updateVisiblePages()` so the re-render is requested at once,
not only on the next paint. Every `PDDocument` access is under `docLock` (PDFBox documents are not
thread-safe); the only lock-free reader is painting, which peeks at the volatile
`pageTexts`.

**Layout/zoom.** `layoutPages()` positions the stack with `doLayout` (works without a
peer, so headless tests see real bounds) and then validates for the on-screen case.
`applyZoom` anchors on a page-relative point in points, never on raw stack pixels, because
the fixed gaps between pages do not scale. Zoom modes `CUSTOM`/`FIT_WIDTH`/`FIT_PAGE`
(fit modes re-apply on viewport resize); `zoomTo(page, ptRect)` fits a page area
(e.g. a search `Match`).

**Lifecycle.** `setPDF(bytes|File|InputStream)` parses off the EDT via `BackgroundTask`; a
`File` goes through `loadSource` (which reads a PDF fully into memory since 2026-10-17, so the
document never refers to its file and can be saved over it): a `.md`/`.markdown` is converted with `MDToPDF` first
(`markdownToPDF`, images relative to the file), an image (`IMAGE_EXTENSIONS`: png, jpg,
jpeg, gif, bmp) becomes a one-page document via the public static `imageToPDF(File)` (A4,
portrait if taller than wide else landscape, image centered inside `IMAGE_MARGIN` = 36 pt,
scaled down to fit and never up; JPEG embedded as DCT via `JPEGFactory`, everything else
decoded with ImageIO, normalized to (A)RGB and stored with `LosslessFactory` — do not hand
the decoded image straight to PDFBox: a two-color palette GIF/PNG is then embedded as 1-bit
gray and loses its color). For both converted kinds (`isConverted`) `getFile()` keeps naming
the source, `saveAs` pre-fills the sibling `.pdf` (`pdfSibling`) and `save` never treats the
origin as the lazily-read source;
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

**Links.** PDF link annotations are clickable (`Link`: page, rect in pt top-left origin,
`getURI()` or `getTargetPage()`). `extractLinks` (under `docLock`) keeps only URI actions
with an `http`/`https`/`mailto` scheme (`isOpenable` — never hand launch/file/JavaScript
targets to the desktop) and GoTo actions / direct or named destinations inside the
document; `PageTransform.of(page).toViewRect(...)` maps the annotation rectangle through
crop box + page rotation.
Links are cached per `PageView` (`links`, rebuilt with the page views after insert/delete),
read lazily on the render thread at first paint (`requestLinks`) so hovering never waits
on `docLock`; `getLinks(page)` / `linkAt(page, xPt, yPt)` read synchronously. Hover
(`updateHover`, `mouseMoved`) shows the hand cursor + tooltip (URI or "Go to page n") —
the tooltip is set on the pages panel, NOT on a `PageView` (a tooltip registers mouse
listeners, and a `PageView` with listeners would swallow the events the pages panel's
adapter relies on). A click = press and release on the same link within `CLICK_SLOP` px
measured in **viewport** coordinates (panning keeps the pointer on the same pages-panel
point) → `followLink`: `Desktop.browse`/`mail`, or `gotoPage` + scroll to the destination's
top (XYZ / FitH, unrotated target pages only). Active with `PAN` and `SELECT_TEXT` (a drag
still pans/selects), not with `ZOOM_TO_SELECTION`. Plain-text URLs without an annotation
are not detected.

**Tools/input.** `Tool` (toolbar toggle group) decides what a plain left drag does, and
each tool is a `PDFToolHandler` strategy (`pressed`/`dragged`/`released`/`moved` (hover, after
the panel applied `cursor()` or the link hand, so a tool can show a move / resize cursor)/`keyPressed`/
`paintOverlay`/`cursor`/`cancel`, fed by the panel's `PDFToolContext` implementation
`ToolContextImpl`; handlers never touch panel fields): `PAN` scrolls (`PanHandler`),
`SELECT_TEXT` selects (`SelectTextHandler`: double click = word, right click = Copy/Select
all/Clear menu), `ZOOM_TO_SELECTION` rubber-bands a rectangle that is fitted to the
viewport (`zoomToViewRect`; the marquee spans pages, so the panel's dispatcher owns it and
`ZoomSelectionHandler` only says `marqueeZoom()`), `CUSTOM` = the host handler installed
with `setCustomTool(handler)` (toggles show no selection). The dispatcher keeps what every
tool shares: Shift+drag marquee, popup trigger (`buildContextMenu(e)`: the host's
`setContextMenuCustomizer(BiConsumer<JPopupMenu, MouseEvent>)` adds its items first, then a
separator and Copy / Select all / Clear selection; public so hosts can test the menu without
showing it, 2026-10-17), link click (`followsLinks()`), hover, focus; `copySelection()` first
asks the host's `setCopyInterceptor(BooleanSupplier)` (true = handled: the PDF editor copies its
selected annotation), so Ctrl+C, the Copy button and the Copy menu entry all share that rule;
`handler.cancel()` runs on Escape, tool change, document change and page-tree refresh. A
handler's `paintOverlay` is painted per page after the highlights, before the border. Keys (WHEN_ANCESTOR bindings on the panel, so they also
work with focus in the toolbar fields): PgUp/PgDn scroll a screen (`scrollBy`),
Ctrl+PgUp/PgDn jump pages, Ctrl+Home/End first/last page, Ctrl +/−, Ctrl+0 fit width,
Ctrl+A/Ctrl+C select all/copy, F3/Shift+F3 next/previous search match (via `runSearch`, so
they also run a not-yet-searched query), Esc clears the selection else returns to `PAN`;
Ctrl+wheel zooms around the pointer. The wheel listener sits on the pages panel, and a component with
a wheel listener never lets wheel events bubble to the enclosing `JScrollPane`
(`Component.dispatchMouseWheelToAncestor` runs only for listener-less components), so the
listener forwards every plain wheel event to `scrollPane.dispatchEvent(...)` itself — remove
that and the wheel only scrolls with the pointer over the scroll bar
(`mouseWheelOverThePagesScrollsAndCtrlWheelZooms` guards it).

**File/print.** Open (`openFile()` → shared `JFileChooser` (`fileChooser(allSources)`:
PDF-only filter for saving, or the PDF+Markdown+images `sourceFilter` for opening and
inserting; read the selection before switching filters, a filter change clears it) →
`setPDF(File)`;
`getFile()` remembers the origin, null for byte/stream documents). Save (`saveAs()`,
`save(File)`: `writeDocument` to a temp file next to the target off the EDT, then moved into
place, for the source file like any other since 2026-10-17: no close, no reload, the document,
page, selection and a host's undo history stay, the delegate hears `documentSaved()`; never
`save` straight onto the target). **Passwords (2026-10-17).** `loadPDF(bytes, name)` (behind
`setPDF` and `loadSource`, so inserts, drops and joined opens too) catches
`InvalidPasswordException` and asks the `PasswordPrompt` (`setPasswordPrompt`; the default is
`GUIUtil.askPassword` on the EDT via `invokeAndWait`, cancelled at once when headless) until a
password is accepted or it returns null, in which case nothing is opened / that file is left out,
without an error. The panel keeps the result as `getSecurity()` (`PDFSecurity.loaded`: the typed
password stands in for the owner password too); `setDocument(doc, owns)` of a host-parsed
encrypted document keeps the permissions but no password. `setSecurity(s)` asks
`EditDelegate.setSecurity` (default false; the editor makes it undoable) else
`setSecurityDirect(s)` (records the value, `modified`, the `security` property change). The
document in memory is **never encrypted**: `writeDocument` removes a loaded encryption
(`setAllSecurityToBeRemoved`, the content is plain in memory) and, for a protected value, saves
plain into memory, loads a copy, `applyTo` on it and writes that, because PDFBox encrypts the
streams in place while saving (the first attempt that protected the live document broke every
later save). Print (`print()`: `PrinterJob`
dialog on the EDT, `job.print()` off the EDT; `createPageable()` wraps PDFBox
`PDFPageable` so every page prints under `docLock`; it is a snapshot guarded by the
`edits` counter, so after `close()` or any insert/delete it reports `NO_SUCH_PAGE` — hosts
create a fresh one after edits). Insert (`insertDialog()` → file chooser accepting `*.pdf`, `*.md` and images
(Markdown is converted with `MDToPDF`, an image wrapped in one page by `imageToPDF`, both
through `loadSource`) + position dialog; `insertPDF(file, index)`
async, `insertDocument(doc, index)` sync primitive; index 0 = beginning, page count = end,
n = after page n. `mergeInto` = `PDFMergerUtility.appendDocument` (deep copy, source may
be closed) then `PDPageTree.remove` + `insertBefore` to move the appended pages into
place; `refreshPages` rebuilds the page views keeping document/zoom/tool and clears
highlights + selection). Merging sets `isModified()`; `save` clears it; `openFile()` and
hosts' window-closing call `confirmDiscard()`. The panel has no undo of its own: an
`EditDelegate` provides it (see *Editing hooks*).
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
with two or more pages.

**Editing hooks.** `setEditDelegate(EditDelegate)`: the delegate is asked first by
`insertDocument` and `deletePages(int[])` (after validation; `true` = handled), answers
`isModified()` (so `confirmDiscard` follows it), and hears `documentReplaced()` once per
`install`/`close` (`install` uses `releaseDocument()`, not `close()`, to avoid a double
notification) and `documentSaved()` after a save that did not reload. With a delegate
installed `refreshPages` no longer sets `modified`. The direct primitives
`insertPagesDirect(PDDocument, int)`, `insertPagesDirect(List<PDPage>, int[] indexes,
showPage)` (each page at its index, in order; ascending original indexes restore the
exact order), `removePagesDirect(List<PDPage>, showPage)` (a removed `PDPage` stays a valid
object of the document, no cloning) and `pagesChanged(showPage)` never ask the delegate and
all go through `refreshPages` (so `edits`/`generation` bump). `getDocumentLock()` exposes
`docLock`. PDPage wrappers are recreated per `getPage` call: compare `getCOSObject()`
(or `PDPage.equals`), never `==`. Also for the editor: `movePagesDirect(pages, targetIndexes,
showPage)` (remove then re-insert each at its index, one lock, one refresh) and
`setRotationsDirect(pages, rotations, showPage)`; `getSelectionRects(page)` (the selection's
glyph rectangles in view space, what a text markup annotation is built from; same source as
a search `Match`'s rects); `showOverlay(comp, page, viewRect)` / `hideOverlay()` / `overlay()` on the tool context
(2026-10-17: a component, the editor's in-place text editor, becomes a child of that page's
`PageView`, placed over the area by `positionOverlay()` from `updateSize` / `doLayout`, so it
scrolls and zooms with the page; one at a time, gone with the page views on a rebuild);
`setAnnotationFilter(AnnotationFilter)` (which annotations the
renderer draws, re-applied to every new renderer in `install`; used to hide the annotation
being dragged); `getToolContext()` (the `PDFToolContext` the panel hands its handlers, so a
host can drive a handler without a mouse); `getSelectionTextPositions(page)` (the selected
characters' `TextPosition`s, separators left out: glyph identity for the in-place text
editor). `invalidatePage` also drops the page's extracted text (`pageTexts[page]`,
`textRequested`), clears a selection touching the page and the search highlights on it,
because the editor may have rewritten the content stream.
`movePages(pageIndexes, target)` (2026-10-17, what a thumbnail drag calls; target = the index
before the move the block lands in front of, page count = the end) asks
`EditDelegate.movePages(pages, target)` (a `default` method returning false) first, else computes
the landing indexes like the editor's `MovePagesEdit` and calls `movePagesDirect`.

**Thumbnails (2026-10-17).** `PDFThumbnailPanel` is the sidebar: one `Thumb` per page
(`THUMB_WIDTH` 100 px wide, height in page proportions, number underneath, the current page
framed in blue), lazily rendered on first paint through `PDFViewerPanel.renderThumbnail(index,
widthPx, generation)` on the shared render thread (`renderExecutor()`), a per-thumb `version`
dropping stale results. The viewer owns it: `setThumbnailsVisible` / `isThumbnailsVisible` /
`getThumbnailPanel()` put its scroll pane WEST of the pages inside the `centre` panel (the pages'
scroll pane is no longer a direct child of the viewer), the toolbar toggle and the
`thumbnailsVisible` property change follow; `PagesPanel.rebuild()` (install, close, every
page-tree refresh) calls `reload()`, `invalidatePage` calls `invalidateThumbnail(page)`, and the
page-change listener frames the current page and scrolls it into view. A click goes to the page;
a drag beyond `DRAG_SLOP` shows a blue insertion line (`dropIndexAt`: upper half = before that
thumbnail, below the last = the end) and the release calls `movePages`. `indexAt`,
`getThumbnailBounds`, `getThumbnailImage`, `requestThumbnail`, `isDragging` are for tests.

**Drag and drop (2026-10-17).** `FileDropHandler` (the panel's `TransferHandler`, so a drop
anywhere on the viewer counts) accepts `javaFileListFlavor` lists with at least one
`acceptsFile` (PDF, Markdown, image) entry and calls `dropFiles(files, panelPoint)` (the point in
pages-panel coordinates, null when not over the pages): the host's
`setDropInterceptor(BiPredicate<List<File>, Point>)` first; with nothing loaded `openFiles`
(one file = `setPDF`, several = converted and joined off the EDT into one unsaved, file-less
document); with a document a dialog asks Open / Insert after page n / Insert at the end, the
dialog-free form being `dropFiles(files, DropAction)`. `insertFiles(files, index)` loads every
source off the EDT, then inserts each through `insertDocument` on the EDT (so an `EditDelegate`
gets one undoable insert per file). `setDefaultDirectory(dir)` is where the choosers start while
no file is open. **Open handler (2026-10-19).** `setOpenHandler(Predicate<List<File>>)` /
`getOpenHandler()`: a host with tabs or windows takes the files the user opens while a document is
loaded; `openFile()` (chooser first, then the handler, then `confirmDiscard` + `setPDF`; the discard
question used to come before the chooser) and `dropFiles(files, OPEN)` ask it (`openHandled`), the
drop dialog then says "Open shows the file on its own" instead of "replaces the current document";
`setPDF` / `openFiles` never ask. The PDF editor's `PDFEditorTabs` opens the files in a new tab.

**Toolbar order.** Open, Save, Print, Insert, Delete, Thumbnails toggle | prev, page field / count, next |
zoom out, zoom combo (presets + fit modes), zoom in | Pan, Select text, Zoom to selection,
Copy | search field, find, previous match, next match (the two arrows are enabled only with
2+ matches), "n / m" | glue, `FontSizeWidget` (control text size). Form editing is out of scope; annotations are the PDF editor's job
(`apps`, `PDF-EDIT-DESIGN.md` Tiers 2-3, not started).

### Hex editor

Moved on 2026-10-15 to the `apps` module, package `io.xlogistx.editor.hex` (`HexEditor`,
`HexPanel`, `HexEditorPane`, `HexEditorFrame`, `HexEditorConsole`, resources
`about.md`/`shortcuts.md`). `apps` depends on this module for `IconUtil` and
`MDViewerPanel`; the design notes are in `apps/CLAUDE.md`.

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
  `error`, `question`, `file`, `folder`, `undo`, `redo`, `print`, `pan`, `select`, `area`,
  `insert`, `pdf`, `camera`, `highlight`, `underline`, `strikeout`, `note`, `pen`, `rectangle`,
  `ellipse`, `line`, `arrow`, `textbox`, `rotate-left`, `rotate-right`, `rotate-image-left`, `rotate-image-right`, `thumbnails`, `move`, `annot-select`,
  `form`, `edit-text`, `picture`). All are Feather-style: 24x24 viewBox,
  `fill="none"`, `stroke="#5A5A5A"`, stroke-width 2, round caps/joins — match this style
  when adding new ones. Each `XxxIcon` class maps to the same-named svg
  (`PlusIcon`→`plus.svg`, ...), except: `EditIcon`→`edit.svg` is a pencil,
  `DeleteIcon`→`delete.svg` is a trash can, `UpdateIcon`→`update.svg` is two chasing
  arrows (sync), `RefreshIcon`→`refresh.svg` is a single clockwise arrow,
  `RollbackIcon`→`rollback.svg` is its counterclockwise mirror, `RunIcon`→`run.svg` is a
  play triangle, `InfoIcon`→`info.svg` is an "i" in a circle, `AreaIcon`→`area.svg` is four
  corner brackets (zoom to selection; `rectangle.svg` is a plain closed rectangle, not a
  duplicate), `PenIcon`→`pen.svg` is a nib with a circle (ink; `edit.svg` is a pencil),
  `RotateLeftIcon`/`RotateRightIcon` are a page outline with a curved arrow (NOT the bare
  arrows of `rollback`/`refresh`), `RotateImageLeftIcon`/`RotateImageRightIcon` the same arrow
  around a framed picture (sun + hills) so the page and image rotate buttons of the PDF editor
  do not look alike, `AnnotSelectIcon` is a cursor over a dashed rectangle
  (`select.svg` is a cursor with a line), `TextBoxIcon` is a T in a box, `FormIcon` a field
  box with a caret. `UndoIcon`/`RedoIcon` are
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
  without an argument it shows a generated multi-page sample (Open/Insert accept PDF,
  Markdown and PNG/JPEG/GIF/BMP files)
- `MDViewerOverrideCheck` — windowless assertion run for
  `MDViewerPanel.overrideScrollPane(...)`; exits 0 on success

Build: `mvn clean install -pl gui-audio -am` (from repo root).

Headless-safe JUnit tests (`src/test/java/io/xlogistx/gui/`): `MDToPDFTest`,
`MermaidRendererTest`, `pdf/PageTransformTest` (hand-computed corners for all four
rotations + offset crop box, and a rendered-pixel check against `PDFRenderer`),
`PDFSecurityTest` (2026-10-17: the value class, a protected file opened through the prompt with a
refused first try and saved still protected then plain after `NONE`, a plain file protected with
separate owner password and restricted permissions and saved twice, a cancelled prompt opening or
inserting nothing, a host-parsed encrypted document keeping its permissions) and
`UIFontSizeTest` (2026-10-17: every look-and-feel font scales in proportion, new components get
the size, a tree is refreshed on request, listeners and the widget follow, steps, clamping and
an exact reset; 2026-10-23: a scoped size scales one tree only, skips the pinned widget, is not
reached by the application size, and the base hands the tree back), `PDFThumbnailPanelTest` (2026-10-17: one thumbnail per page in page proportions, the current
page framed, a click jumps, a drag moves a page directly or through the delegate, the drop
index, pictures rendered off the EDT and dropped by `invalidatePage`; the launcher classpath for
this module is the `-X` `testPath` of `test-compile -pl gui-audio` plus the junit launcher /
engine jars), `PDFViewerPanelTest` (its `viewport()` helper finds the pages' scroll pane
recursively, skipping the sidebar's; sets `java.awt.headless=true`, lays the component tree out by hand
because `validate()` needs a peer, drives the panel through `invokeAndWait`; renders are
requested by `updateVisiblePages`, nothing paints headless). The other
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
