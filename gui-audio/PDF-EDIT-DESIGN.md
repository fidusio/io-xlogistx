# PDFViewerPanel Editing — Design

Status: **approved scope, not started** (2026-09-25).
Scope decision: Tiers 1–3 below. **Forms (AcroForm filling) are out.** In-place editing of
existing page text and true redaction are out (see *Non-goals*).

Companion docs: `gui-audio/CLAUDE.md` (current viewer internals), this file (the editing
design). When implementation starts, keep the *Progress* section at the bottom current.

---

## 1. Goals

- Edit a loaded PDF inside `PDFViewerPanel` without new dependencies: **PDFBox only**.
- Editing is **opt-in** (`setEditable(true)`); the default viewer behaves exactly as today.
- Every edit is **undoable** (bounded stack, like `HexEditor`), including the existing
  Insert and Delete page operations.
- Interaction never re-rasterizes a page while the mouse is down; edits re-render **only
  the pages they touched**.
- The result is a normal PDF: edits are stored as page rotation / page order changes and
  standard PDF **annotations** with appearance streams, readable by every viewer.

## 2. Non-goals (decided, do not revisit without a new decision)

| Excluded | Why | Offer instead |
|---|---|---|
| Editing existing body text in place | PDF has no text model: subset fonts lack glyphs, kerned arrays, no reflow. Every attempt ends as a half-broken feature. | Free-text annotation (Tier 3); for `.md`-origin files edit the Markdown and regenerate (`MDViewerDemo` already does this live). |
| Redaction | A covering rectangle is **not** removal; the text stays extractable. Shipping it would mislead users. | Nothing. State it in the UI if asked. |
| AcroForm field filling | Out by decision (2026-09-25). | — |
| Digital signatures | Different problem (incremental save, certificates). | `opsec` module if ever needed. |

## 3. Feature tiers

### Tier 1 — page operations
- **Rotate** page(s) 90° CW / CCW (`PDPage.setRotation`). Selection syntax = the existing
  `parsePageSelection` (current, `a-b`, lists).
- **Move / reorder** pages: dialog "Move pages `<selection>` to: beginning / end / after
  page n" (same position dialog as Insert). `PDPageTree.remove` + `insertBefore`, the
  mechanics `mergeInto` already uses. Thumbnail drag-reorder is **not** in this tier.
- **Undo / Redo** for rotate, move, and the existing insert and delete.

### Tier 2 — text markup and notes
- **Highlight / Underline / Strikeout** the current text selection (`Tool.SELECT_TEXT`
  selection → one `PDAnnotationTextMarkup` per page in the selection; QuadPoints from
  `PageText.rects(start, end)`). Also available as tools: drag over text = select + mark
  in one gesture.
- **Sticky note** (`PDAnnotationText` + `PDAnnotationPopup`): click places it, a dialog
  edits the contents; double-click an existing note reopens the dialog.
- **Delete annotation** (select + Delete key / context menu).

### Tier 3 — drawing
- **Ink** (freehand polyline, `PDAnnotationInk`), **Rectangle** (`PDAnnotationSquare`),
  **Ellipse** (`PDAnnotationCircle`), **Line / Arrow** (`PDAnnotationLine`, ending style
  `OpenArrow` for arrows), **Free text** box (`PDAnnotationFreeText`).
- **Select** tool for annotations: click selects, drag moves, eight handles resize (ink:
  move only; line: move plus two endpoint handles), Delete removes, a properties popup
  edits stroke colour, fill colour, opacity, stroke width, font size, note text.

---

## 4. Architecture

```
PDFViewerPanel (Swing, io.xlogistx.gui)                io.xlogistx.gui.pdf (no Swing)
+------------------------------------------+          +---------------------------------+
| toolbar (view row + edit row)            |          | PDFEditModel                    |
| PagesPanel / PageView[]  -- paints --+   |  apply/  |   undo/redo stacks (<=100)      |
|   raster (PageCache) + highlights    |   |  revert  |   modified flag, listeners      |
|   + ToolHandler.paintOverlay <-------+   | <------> | PDFEdit (command interface)     |
| ToolHandler per Tool (strategy)          |          |   RotatePagesEdit, MovePagesEdit|
|   PAN, SELECT_TEXT, ZOOM_TO_SELECTION,   |          |   InsertPagesEdit, DeletePages..|
|   HIGHLIGHT, UNDERLINE, STRIKEOUT, NOTE, |          |   AddAnnotationEdit, Remove..,  |
|   INK, RECTANGLE, ELLIPSE, LINE, ARROW,  |          |   ModifyAnnotationEdit          |
|   FREE_TEXT, SELECT_ANNOTATION           |          | PageTransform (pt <-> PDF space)|
| ToolContext (what handlers may touch)    |          | AnnotationStyle (colours, width)|
| docLock, generation, RENDER_EXECUTOR     |          | AnnotationFactory (build + AP)  |
+------------------------------------------+          +---------------------------------+
```

Rules that carry over unchanged: every `PDDocument` access under `docLock`; rendering on
the single `RENDER_EXECUTOR`; painting is lock-free; zero-based page indexes in the API.

### 4.1 `io.xlogistx.gui.pdf.PDFEditModel` (new, pure Java, testable headless)

```java
public final class PDFEditModel {
    public interface Listener { void edited(PDFEditModel m, PDFEdit e, boolean undo); }
    public PDFEditModel(PDDocument doc, Object lock);          // lock = panel's docLock
    public void apply(PDFEdit edit) throws IOException;        // apply + push, clears redo
    public boolean canUndo(); public boolean canRedo();
    public PDFEdit undo() throws IOException;  public PDFEdit redo() throws IOException;
    public boolean isModified();  public void markSaved();     // save -> clean, stacks kept
    public void reset(PDDocument doc);                          // new document: stacks cleared
    public int getUndoDepth();                                   // bounded MAX_UNDO = 100
    public void addListener(Listener l); public void removeListener(Listener l);
}

public interface PDFEdit {
    String name();                                   // "Rotate 2 pages", for tooltips
    void apply(PDDocument doc) throws IOException;
    void revert(PDDocument doc) throws IOException;
    /** Zero-based pages whose raster must be dropped after apply/revert. */
    int[] affectedPages();
    /** True when the page tree changed (count/order/size) -> full refreshPages. */
    boolean structural();
}
```

Commands and their revert strategy:

| Edit | apply | revert | structural |
|---|---|---|---|
| `RotatePagesEdit(pages, delta)` | `setRotation((r+delta) mod 360)` | restore captured rotations | yes (page size changes) |
| `MovePagesEdit(pages, target)` | remove + `insertBefore`, record old positions | move back by recorded positions | yes |
| `InsertPagesEdit(source, at)` | `mergeInto` logic (moved from panel), keep the appended `PDPage` list | `tree.remove(page)` for each kept page | yes |
| `DeletePagesEdit(pages)` | capture `(index, PDPage)` pairs, remove highest first | `insertBefore`/`add` back lowest first | yes |
| `AddAnnotationEdit(page, annot)` | `page.getAnnotations().add`, `constructAppearances()` | `annotations.remove(annot)` | no |
| `RemoveAnnotationEdit(page, annot)` | remove (remember position in list) | re-add at position | no |
| `ModifyAnnotationEdit(page, annot, before, after)` | copy `after` into the annotation's `COSDictionary`, rebuild AP | copy `before` back, rebuild AP | no |

Notes:
- A `PDPage` removed from the tree stays a valid object of the same document, so
  delete-undo just reinserts it. Do not clone.
- `ModifyAnnotationEdit` snapshots are shallow `COSDictionary` copies of the keys the UI can
  change (`Rect`, `QuadPoints`, `InkList`, `L`, `C`, `IC`, `CA`, `BS`, `DA`, `Contents`,
  `Vertices`). Popup annotations of notes move with their parent (`Popup` key).
- Drag interactions produce **one** `ModifyAnnotationEdit` on release, never per mouse move.
- `PDFEditModel.reset` is called from `install(...)` and `close()`; `markSaved` from the
  save callback. Saving over the source reloads the document (see 4.8), which resets the
  stacks — document this in the UI tooltip ("Undo history is cleared when saving over the
  open file").

### 4.2 `PageTransform` (new, in `io.xlogistx.gui.pdf`)

The single source of truth for coordinates. Viewer space = points, origin top-left of the
**displayed** (rotated, crop-box) page, exactly what `PageText`/`Match` use today.

```java
public final class PageTransform {
    public static PageTransform of(PDPage page);         // cropBox, mediaBox fallback, rotation
    public float widthPt(); public float heightPt();      // displayed size (rotation applied)
    public AffineTransform viewToPdf();                  // top-left pt -> PDF user space
    public AffineTransform pdfToView();
    public PDRectangle toPdfRect(Rectangle2D viewRect);  // normalized
    public Rectangle2D toViewRect(PDRectangle r);
    public float[] toQuadPoints(List<Rectangle2D.Float> viewRects); // x1y1 UL, x2y2 UR, x3y3 LL, x4y4 LR
}
```

Derivation mirrors `PDFRenderer`: translate by `-cropBox.lowerLeft`, flip Y over
`cropBox.height`, then rotate by `page.getRotation()` about the box. `PageView` computes its
size from `PageTransform` instead of its own crop-box/rotation code. Unit tests cover
rotation 0/90/180/270 and a crop box with a non-zero origin, by round-tripping corner points
and by comparing against a rendered pixel of a known rectangle annotation.

### 4.3 `AnnotationFactory` + `AnnotationStyle` (new)

`AnnotationStyle` is an immutable value: `strokeColor`, `fillColor` (nullable), `opacity`
(0–1), `strokeWidth` (pt), `fontSize` (pt), `author`. Per-tool defaults live in the panel
(highlight yellow, note yellow, ink/shapes red 2 pt, free text black 12 pt) and are
remembered per session.

`AnnotationFactory` builds each annotation from viewer-space geometry + style and calls
`constructAppearances()`:

- `textMarkup(subtype, quadRects)` — Highlight / Underline / StrikeOut; `Rect` = union of quads.
- `note(pointPt, contents)` — `PDAnnotationText`, name `Comment`, plus a `PDAnnotationPopup`
  (`Open=false`) registered on the page and linked both ways.
- `ink(List<List<Point2D>> strokes)` — one `InkList` array per stroke, `Rect` = bounds + width.
- `square(rect)`, `circle(rect)` — with `BS` width, `C` stroke, `IC` fill.
- `line(p1, p2, arrow)` — `L`; `LE = [None OpenArrow]` when `arrow`.
- `freeText(rect, text)` — **custom appearance** (see 4.9), `DA` kept for other viewers.

All set `M` (modified date), `T` (author), `CA` (opacity), `P` (page), and `F = Print`.

### 4.4 Tool handling as a strategy

The mouse adapter in `installInputHandlers` becomes a dispatcher over `ToolHandler`s.
Package-private abstract class in `io.xlogistx.gui` (new file `PDFToolHandlers.java`
holding all concrete handlers), fed by a narrow `ToolContext` interface implemented by the
panel so handlers never touch panel fields directly:

```java
interface ToolContext {                       // implemented by PDFViewerPanel
    int[] hitPage(Point pagesPanelPoint);    // {page, xPt, yPt} or null (reuse hitTest)
    Point2D toPagePt(int page, Point p);  Point toPanelPoint(int page, Point2D pt);
    float zoom();  PDFEditModel model();  PDDocument document();  Object docLock();
    AnnotationStyle style(Tool t);  void repaintPage(int page);  void invalidatePage(int page);
    // text selection primitives the markup tools reuse
    void select(int sp, int si, int ep, int ei);  int[] selectionRange();  PageText pageText(int page);
    void setCursor(Cursor c);  void showError(String msg);  JComponent owner();
}

abstract class ToolHandler {
    void activated(ToolContext c) {}   void deactivated(ToolContext c) {}
    boolean pressed(ToolContext c, MouseEvent e)  { return false; }  // true = consumed
    void dragged(ToolContext c, MouseEvent e) {}
    void released(ToolContext c, MouseEvent e) {}
    void paintOverlay(ToolContext c, int page, Graphics2D g2) {}   // in page pixels
    void keyPressed(ToolContext c, KeyEvent e) {}
    Cursor cursor() { return Cursor.getDefaultCursor(); }
}
```

Migration: `PanHandler`, `SelectTextHandler`, `ZoomSelectionHandler` are extracted first with
**no behaviour change** (Shift+drag marquee and popup trigger stay in the dispatcher). Then
`TextMarkupHandler(subtype)`, `NoteHandler`, `InkHandler`, `ShapeHandler(kind)`,
`LineHandler(arrow)`, `FreeTextHandler`, `SelectAnnotationHandler`.

`Tool` enum grows to: `PAN, SELECT_TEXT, ZOOM_TO_SELECTION, SELECT_ANNOTATION, HIGHLIGHT,
UNDERLINE, STRIKEOUT, NOTE, INK, RECTANGLE, ELLIPSE, LINE, ARROW, FREE_TEXT`. Edit tools are
only selectable when `isEditable()`; `setEditable(false)` while an edit tool is active falls
back to `PAN`. `Esc` keeps its meaning: clear selection, else `PAN`.

### 4.5 Rendering: per-page invalidation

Today the only invalidation is `cache.clear()` + a global `generation` bump. Editing needs:

- `PageCache.remove(int page)`.
- `PageView.contentVersion` (int, EDT-owned). `invalidatePage(page)` increments it, removes
  the cache entry and repaints. `requestRender` captures the version and drops a finished
  image whose version is stale (same pattern as the existing `z != zoom` check).
- `PageCache.Entry` gains `version` so a stale-but-present image is repainted immediately
  and re-requested (mirrors `entry.zoom != zoom`).
- Structural edits (`structural() == true`) keep using `refreshPages` (rebuild views, clear
  highlights and selection). `refreshPages` no longer sets `modified` itself; the model does.

While the user drags an existing annotation the raster still shows it at the old place.
Acceptable for v1; optional polish: `PDFRenderer.setAnnotationsFilter` excluding the
selected annotation + invalidate on select/deselect. Not in the plan.

### 4.6 Overlay painting

`PageView.paintComponent` order: white, raster, `paintHighlights`, `tool.paintOverlay`,
selection handles (from `SelectAnnotationHandler`), border. Overlays draw in page pixels:
handlers keep geometry in **points** and multiply by `c.zoom()` at paint time, exactly like
`paintHighlights`, so zooming mid-gesture stays correct.

### 4.7 Annotation selection and properties

`SelectAnnotationHandler`:
- Hit test: on press, iterate `page.getAnnotations()` (under `docLock`, EDT), skip `Popup`
  and `Link`, transform `Rect` to view via `PageTransform`, top-most (last) wins; a 4 px
  tolerance around lines/ink.
- Selected state: `(page, PDAnnotation)`; painted as a dashed bounds rectangle with 8 handles
  (6x6 px, not scaled). Line annotations: two endpoint handles only. Ink: move only.
- Drag: move (inside) or resize (on a handle); geometry updated in a working copy, committed
  as one `ModifyAnnotationEdit` on release. Resizing a text markup is disallowed (quads
  belong to glyphs); moving it is allowed.
- Delete key / context menu **Delete** → `RemoveAnnotationEdit`.
- Double-click → note/free-text contents dialog; context menu **Properties…** → small
  `JDialog` bound to `AnnotationStyle` (colour buttons via `JColorChooser`, opacity slider,
  width spinner, font size spinner). OK commits one `ModifyAnnotationEdit`.

### 4.8 Save, print, close, reload

- `save`/`saveAs` unchanged: `PDDocument.save` writes annotations. Save calls
  `model.markSaved()`; save-over-source reloads via `install`, which calls `model.reset`
  (undo history gone — see 4.1).
- `createPageable` already renders under `docLock`, so prints include annotations
  (`F = Print` is set). The `edits` counter still guards it; every **structural** edit bumps it.
- `confirmDiscard()` reads `model.isModified()`.
- `close()` → `model.reset(null)`, active edit tool → `PAN`.
- **Flatten** is an explicit export (`exportFlattened(File)`): on a copy of the document
  (save to temp, reload), for each annotation with a normal appearance draw its form
  XObject into the page via `PDPageContentStream(APPEND, true, true)`, then remove the
  annotation. Not a toolbar button in v1; API only. Optional, last item of Tier 3.

### 4.9 Free-text font

PDFBox's `PDFreeTextAppearanceHandler` uses Helvetica: non-Latin-1 text renders as boxes.
`AnnotationFactory.freeText` builds the appearance stream itself: a `PDAppearanceStream`
whose resources embed the Roboto TTF already shipped by `flatlaf-fonts-roboto` (same
loading code path as `MDToPDF`; `PDType0Font.load(doc, stream, true)`, one font per document
cached in the factory), word-wrapped to the box, border/background from the style. `DA`
still says `/Helv <size> Tf` so other editors can re-generate.

### 4.10 Threading

- All edits run on the **EDT under `docLock`**. An edit waits for any in-flight page render
  (tens to hundreds of ms); no second locking scheme.
- `RENDER_EXECUTOR` stays the only place that renders or extracts text.
- `PDFEditModel` is not thread-safe by itself; the panel guarantees EDT access. Tests call
  it from the test thread with the document lock, which is fine because nothing renders.

### 4.11 Toolbar and icons

Two rows when editable (`JToolBar`s inside a `JPanel` with a vertical `BoxLayout`; the
existing `getToolbar()` keeps returning the view row; new `getEditToolbar()`):

```
view row: Open, Save, Print, Insert, Delete | Pan, Select text, Zoom to selection, Copy | prev, page / n, next | zoom out, combo, zoom in | search, next, n/m   (unchanged)
edit row: [Edit] | Undo, Redo | Rotate CCW, Rotate CW, Move pages | Highlight, Underline, Strikeout, Note | Ink, Rect, Ellipse, Line, Arrow, Text box | Select annot. | stroke, fill, opacity, width, size
```

`[Edit]` is a toggle that calls `setEditable`; the rest of the row is disabled when off. The
property strip reflects the active tool's `AnnotationStyle` or the selected annotation.

New SVGs (Feather style, 24x24, stroke `#5A5A5A`, width 2; **no glyph may duplicate an
existing one**, cf. the rule in `gui-audio/CLAUDE.md`): `highlight` (marker pen),
`underline`, `strikeout`, `note` (speech bubble), `pen` (ink nib), `rectangle`,
`ellipse`, `line`, `arrow`, `textbox` (T in a box), `rotate-left` / `rotate-right` (page
outline with a curved arrow — must **not** read as `refresh`/`rollback`), `move` (page
with up/down arrows), `annot-select` (cursor over a rectangle; distinct from `select`).
Each gets a `XxxIcon` class in `IconUtil`'s pattern. Reuse `EditIcon`, `UndoIcon`,
`RedoIcon`, `DeleteIcon`.

Key bindings added (WHEN_ANCESTOR, like the others): Ctrl+Z undo, Ctrl+Y / Ctrl+Shift+Z
redo, Delete = remove selected annotation, Ctrl+Shift+H highlight selection.

### 4.12 Public API additions on `PDFViewerPanel`

```java
PDFViewerPanel setEditable(boolean on);   boolean isEditable();
PDFEditModel   getEditModel();            // null when no document
boolean canUndo(); boolean canRedo();  PDFViewerPanel undo();  PDFViewerPanel redo();
PDFViewerPanel rotatePages(int[] pages, int deltaDegrees);      // +-90, +-180
PDFViewerPanel movePages(int[] pages, int targetIndex);          // like insert positions
int  markSelection(MarkupKind kind);                              // HIGHLIGHT|UNDERLINE|STRIKEOUT, returns annotations added
PDAnnotation addNote(int page, Point2D pt, String text);
PDAnnotation addAnnotation(int page, PDAnnotation a);            // generic, undoable
boolean removeAnnotation(int page, PDAnnotation a);
List<PDAnnotation> getAnnotations(int page);                     // snapshot, no Popups
PDAnnotation getSelectedAnnotation();  PDFViewerPanel selectAnnotation(int page, PDAnnotation a);
AnnotationStyle getStyle(Tool t);  PDFViewerPanel setStyle(Tool t, AnnotationStyle s);
JToolBar getEditToolbar();
void exportFlattened(File target);                               // Tier 3, optional
```

`insertDocument`, `insertPDF`, `deletePages` keep their signatures and now go through the
model (undoable). `isModified()` delegates to the model.

---

## 5. Phasing and acceptance

### Phase 0 — foundation (no new user-visible tool, Undo/Redo appears)
1. New package `io.xlogistx.gui.pdf`: `PDFEdit`, `PDFEditModel`, `PageTransform`,
   `AnnotationStyle`, `AnnotationFactory` (markup + note only for now), `InsertPagesEdit`,
   `DeletePagesEdit`.
2. `PDFViewerPanel`: `PageCache.remove`, `contentVersion`, `invalidatePage`; `PageView`
   sized from `PageTransform`; `ToolContext` + `ToolHandler` with the three existing tools
   extracted; `setEditable`; edit row with Edit toggle + Undo/Redo; insert/delete routed
   through the model.
3. Tests: `PDFEditModelTest` (apply/undo/redo/bounds/reset), `PageTransformTest` (four
   rotations + offset crop box), `PDFViewerPanelTest`: existing tests green unchanged +
   `insertThenUndoRestoresPageCount`, `deleteThenUndoRestoresSamePageObjects`.
   Accept when: `toolsToggleAndSetTheCursor`, `insertsPagesAtBeginningEndAndAfterAPage`,
   `saveWritesLoadablePDF` pass without modification.

### Phase 1 — Tier 1
`RotatePagesEdit`, `MovePagesEdit`, rotate/move dialogs, icons `rotate-left`,
`rotate-right`, `move`. Tests: rotation persists after save/reload; move `[2,3]` to
beginning yields the expected subject order (compare extracted text per page); undo returns
the original order.

### Phase 2 — Tier 2
`TextMarkupHandler`, `NoteHandler`, `SelectAnnotationHandler` (select/move/delete only),
`markSelection`, `addNote`, icons `highlight`, `underline`, `strikeout`, `note`,
`annot-select`. Tests: highlight from a two-page selection creates two annotations with
QuadPoints inside the page box and matching `PageText.rects`; saved file reloads with the
annotations; `constructAppearances` produced an `/AP`; rendered pixel at a highlighted glyph
is yellowish; undo removes both; note popup is linked both ways.

### Phase 3 — Tier 3
`InkHandler`, `ShapeHandler`, `LineHandler`, `FreeTextHandler` (custom Roboto appearance),
resize handles, properties dialog, `ModifyAnnotationEdit`, property strip, remaining icons,
optional `exportFlattened`. Tests: shape rect round-trips through `PageTransform` on a
rotated page; move by (10, 20) pt updates `Rect` exactly; free text with non-Latin text
renders non-blank pixels; flattened export has zero annotations and identical rendering hash.

### Docs to update when each phase lands
- `gui-audio/CLAUDE.md`: replace "Annotations and form editing are intentionally out of
  scope" and "No undo — reopen the file instead" with the new rules; add the new icons to
  the SVG list; add the `pdf` package to the architecture section.
- Root `CLAUDE.md` module table: mention editing.
- `PDFViewerDemo`: start with `setEditable(true)`.

---

## 6. PDFBox facts this design relies on (verified against pdfbox-3.0.8.jar)

- Appearance handlers exist for Caret, Circle, FreeText, Highlight, Ink, Line, Link,
  Polygon, Polyline, Square, Squiggly, StrikeOut, Text, Underline;
  `PDAnnotation.constructAppearances()` / `constructAppearances(PDDocument)` drive them.
  PDFBox **renders annotations only through their appearance streams**, so every create or
  modify must rebuild the AP.
- `PDFRenderer.setAnnotationsFilter(AnnotationFilter)` is available for the optional
  hide-while-dragging polish.
- `PDPageContentStream(doc, page, AppendMode, resetContext, resetGraphicsState)` exists for
  flattening.
- Text markup QuadPoints order: `x1 y1` upper-left, `x2 y2` upper-right, `x3 y3` lower-left,
  `x4 y4` lower-right, in PDF user space; `Rect` must enclose all quads or some viewers clip.
- A `PDPage` removed via `PDPageTree.remove` remains usable for `insertBefore`/`add`
  (basis for delete-undo).

## 7. Risks

| Risk | Mitigation |
|---|---|
| Coordinate bugs on rotated / offset pages | `PageTransform` is the only conversion; tested in isolation before any tool is built. |
| Panel file grows past 3 000 lines | Handlers in `PDFToolHandlers.java`, model in `io.xlogistx.gui.pdf`. |
| Edit blocked behind a slow render under `docLock` | Renders are per page and short; accepted. Do not add a second lock. |
| Existing embedders see UI changes | `setEditable` default `false`; view row identical. |
| Non-Latin free text | Custom appearance with embedded Roboto (4.9). |

## 8. Progress

- [ ] Phase 0 foundation
- [ ] Phase 1 Tier 1 page operations
- [ ] Phase 2 Tier 2 markup + notes
- [ ] Phase 3 Tier 3 drawing
