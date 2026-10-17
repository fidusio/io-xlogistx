# apps module

Standalone applications built on the other modules (`gui-audio` for Swing widgets,
icons and the Markdown viewer). Java package base `io.xlogistx`.

## PDF editor (`io.xlogistx.editor.pdf`)

All of `gui-audio/PDF-EDIT-DESIGN.md` (Phase 0, Tiers 1–3) plus AcroForm filling, landed
2026-10-15; the design's "Decisions 2026-10-15" section says what differs from its section 4
and which PDFBox APIs differ from the doc. Built on `gui-audio`'s `PDFViewerPanel` hooks
(`EditDelegate`, direct page primitives, `PDFToolHandler`/`PDFToolContext`/`Tool.CUSTOM`,
`invalidatePage`, `getSelectionRects`, `setAnnotationFilter`, `getToolContext`,
`io.xlogistx.gui.pdf.PageTransform`). Standalone: `io.xlogistx.editor.pdf.Main [file]`.

**Edits** (all `PDFEdit`, EDT, through `PDFEditModel`): `InsertPagesEdit`, `DeletePagesEdit`,
`RotatePagesEdit` (captures rotations, `setRotationsDirect`), `MovePagesEdit` (Insert
positions: `target` = index the block lands in front of, before the move; `getLandingIndexes`),
`AddAnnotationEdit` / `RemoveAnnotationEdit` (a note's popup travels with it; list position
remembered; identity by `getCOSObject()`, `getAnnotations()` wraps afresh each call),
`ModifyAnnotationEdit` (snapshots of the `TRACKED` keys before/after; apply/revert write a
snapshot, move the popup, `AnnotationFactory.rebuildAppearance`, `invalidatePage`; one per
gesture), `SetFieldValueEdit` (String, or `List<String>` for multi-select; check box via
`check()/unCheck()`, choice cleared with `setValue((String) null)`; `refreshAppearances`
when `NeedAppearances`; invalidates every page with a widget), `CompoundEdit` (one step for
several, e.g. a highlight spanning pages).

**Annotations**: `AnnotationStyle` (immutable: stroke, fill (nullable), opacity, width, font
size, font family + `java.awt.Font` style bits (bold / italic; 2026-10-16), author; defaults
`HIGHLIGHT`, `UNDERLINE`, `NOTE`, `DRAWING`, `TEXT`; `underline` / `strikethrough` / `highlightColor` (a
band behind the text, not the box fill) / `alignment` (`TextEditor.Alignment`, the annotation's
standard `Q`) for text boxes, 2026-10-16),
`EditorFonts` (the fonts text is written with: `families()` = bundled `Roboto` first, then the
runtime's font families; `load(doc, family, style)` gives a **fresh** subset `PDType0Font` per
use from font bytes cached per family + style: the bundled faces from the `flatlaf-fonts-roboto`
TTFs, a system family through `new Font(family, style).getPSName()` + PDFBox `FontMappers`
(a fallback mapping is refused with an `IOException`; the mapper's shared `TrueTypeFont` is
copied via `getOriginalData()`, never handed to PDFBox, because `subset()` wrecks it; TTC
collections cannot be embedded). **`seal(doc, font)` after the text is written**: PDFBox writes
a subset font's program + ToUnicode only in `subset()`, once, normally at save, and until then
the page renders and extracts *wrong glyphs* through a fallback (`'first'` read as `'gjstu'`
with Roboto Bold); `seal` calls `subset()` at once and removes the font from
`doc.getFontsToSubset()` (a second `subset()` throws). A sealed font must not get new text:
hence one font object per appearance build / text replacement. `styleOf(font)` (name +
descriptor flags) and `familyOf(font)` (descriptor family or base name minus subset tag,
face and MT/PS tails, matched against `families()` ignoring case and spaces) let the
in-place editor load another face of a page font's family), `AnnotationFactory`
(view-space geometry + style → `PDAnnotationHighlight/Underline/Strikeout` (quads from
`PageTransform.toQuadPoints`), `PDAnnotationText` + linked `PDAnnotationPopup`, `Ink`,
`Square`/`Circle`, `Line` (open arrow), `FreeText` (`DA = "/Helv size Tf r g b rg"`, `DS =
"font-family: X; font-weight: bold; font-style: italic; text-decoration: underline line-through;
…; background-color: #RRGGBB"` for the family, face, underline, strikethrough and text highlight, `C` =
background), `image` → `PDAnnotationRubberStamp` (`/Stamp`, name `Image`); all `setPrinted`,
dated, titled, `setConstantOpacity`; `constructAppearances` except free text and stamps),
`ImageStamp` (the picture is the stamp's own normal appearance: `PDImageXObject` kept in the
appearance resources as `Im0`, drawn to fill `Rect` with an ExtGState for the opacity; PDFBox
has no stamp handler, so `rebuild` redraws from that XObject after a resize or rotation without
re-encoding; rotation (2026-10-16) is a private `/Rotate` key on the annotation, degrees clockwise
in quarter turns like a page, drawn into the appearance (so other viewers show it) by rotating about
the box centre and drawing the picture with the box sides swapped; `rotate(a, delta, within)`
adds a quarter turn, swaps the box width/height about its centre and shifts it back onto the
page; `ROTATION_KEY` is in `ModifyAnnotationEdit.TRACKED`; `isImage`/`imageOf`/`rotationOf`/
`aspect` (inverted for 90/270)), `FreeTextAppearance` (own `/AP` with the font `EditorFonts` gives for
the DS family + face, sealed after drawing, falling back to the bundled family when it cannot be
loaded; word wrap, missing glyphs → `?`, Helvetica fallback; an underline / strikethrough (DS
`text-decoration: underline line-through`) is a filled bar per line, `UNDERLINE_DROP` 0.12 em
below / `STRIKE_RISE` 0.28 em above the baseline, `UNDERLINE_THICKNESS` 0.06 em;
a text highlight (DS `background-color`) is a band per line from `HIGHLIGHT_DESCENT` 0.25 em
below the baseline, `HIGHLIGHT_HEIGHT` 1.2 em tall, painted before the text; `defaultStyle(style)`
writes DS, `fontFamily(ds)` / `fontStyle(ds)` / `underline(ds)` / `strikethrough(ds)` /
`highlight(ds)` read it back; lines start at `inset + (room - width) × {0, ½, 1}` for `Q` 0 / 1 / 2
(`q(alignment)` / `alignment(q)`), bars and bands follow), `AnnotationGeometry` (`Kind` MOVE_ONLY / BOX (incl. stamps) / LINE, `hitTest`
topmost-first skipping Popup/Link/Widget with a tolerance for lines and ink, `translate`
shifts Rect/QuadPoints/InkList/L/Vertices + popup, `setBounds`, `setLine`), `FormFields`
(terminal fields, `isFillable` = text/check/radio/choice and not read-only, `widgetsOn(page)`
with view rects, `pagesOf(field)`, `valueOf`).

**In-place text editing** (`TextEditor`, pure PDFBox, under the lock): `glyphs(page)` walks
the page's own content stream with a `PDFStreamEngine` subclass (text + state operators
registered, forms skipped, a depth guard because `'`/`"` re-enter `processOperator`) and
records (operator index, string index in a `TJ`, code index, unicode, font, origin, advance,
the `Tf` resource name (tracked through q/Q), the fill colour as RGB (colour operators
registered too) and the text rendering matrix + CTM) per glyph; `match(glyphs, t, selectionTextPositions)` ties the viewer's selection to glyphs by
unicode + position (`TextPosition.getXDirAdj/getYDirAdj` == `PageTransform.toView(origin)`,
tolerance 0.75 pt); `replace(page, glyphs, text)` re-splits the string operand by
`font.readCode`, drops the selected codes, inserts `font.encode(text)` at the first, wrapped in
`TJ` adjustments that place it by `Alignment` (LEFT keeps the old start, RIGHT the old end,
CENTER the middle; computed from the old glyphs' advances + char/word spacing vs
`font.getStringWidth(text)`) and keep the rest of the string where it was (`Tj`/`'`/`"`
operators become `TJ`), and writes the tokens back with `ContentStreamWriter`; `encode` names every character the font
lacks (subset fonts only know the glyphs the document uses). `replace(doc, page, glyphs, text,
alignment, Format)` (2026-10-16) can also change the font (any `EditorFonts` family + style,
embedded, sealed and added to the page resources), the face alone (`Format.fontStyle` bits with a
null family: `EditorFonts.familyOf` the page font and load that family's face, refused with a
"pick a font" message when the family is not installed; `KEEP_STYLE` keeps the face), the
rendered size (the `Tf` operand is scaled by
the old operand / rendered-height ratio) or the colour: the string is then split into three
`TJ`s with `/Fnew size Tf` + `r g b rg` before the replacement and the old `Tf` operand and
colour after it (RGB equivalent for other colour spaces), the alignment adjustments staying in
the old font's runs; `Format.SAME` keeps the single-`TJ` output. `Format.underline` /
`strikethrough` add a stroked line under / through the replacement right after the enclosing
`ET` (`lineTokens(…, riseEm)`: start and end through the glyph's `trm` so it follows rotated
text, mapped back through the inverse CTM because it is emitted inside that state, drop / rise /
thickness from `FreeTextAppearance`, in the text colour, wrapped in q/Q). `Format.highlight` adds
a filled band (`bandTokens`, same geometry, `HIGHLIGHT_DESCENT` / `HIGHLIGHT_HEIGHT`) emitted
*before* the `BT` that opens the replacement's text object (found by a pre-scan; at the stream
start when there is none), so the text stays on top and no path operator lands inside BT/ET. `ReplaceTextEdit` swaps the
whole content stream (before/after bytes; a font added to the resources stays, unused, after
undo). No reflow and no text inside form XObjects are the accepted limits; a wider
replacement overlaps what follows.

**Tools** (`io.xlogistx.editor.pdf.tools`, `EditorTool extends PDFToolHandler`, fed by the
pane as `EditorHost`): `EditTextTool` (selects like the text tool; double click a word or
Enter opens the replacement dialog, which shows the old text's rendered size, colour and face
(Bold / Italic pre-ticked from `EditorFonts.styleOf`), Underline / Strikethrough boxes, a Highlight
colour button (none by default) and a font list
starting with "keep the current font"; `replaceSelection(c, text, alignment, Format)` for
API use, one page only),
`TextMarkupTool(kind)` (drag selects, release marks; static `mark`
for an existing selection), `NoteTool` (click → text dialog), `InkTool` (points ≥ 1.5 pt
apart, one stroke per drag), `ShapeTool(circle)`, `LineTool(arrow)`, `FreeTextTool` (drag or
click = 160x40 pt, text dialog), `ImageTool` (drag a box or click, then an image file chooser;
`placement` fits the picture into the box keeping its aspect ratio, a click uses the pixel
size at 72 dpi capped to half the page and shifted onto it; `addImage(File|BufferedImage)`
for API use: `createFromFileByContent` keeps JPEG as DCT, everything else goes through
`LosslessFactory`; the placed picture is handed to the selection tool at once through
`EditorHost.selectWithTool`, and a press on an existing picture with the Image tool does the
same and forwards the press, so the drag continues as a move), `SelectAnnotationTool` (hit
test, move / 8 resize handles / line endpoints on a working copy painted as overlay while
`setAnnotationFilter` hides the original, one `ModifyAnnotationEdit` on release; a drag on
empty space pans like the pan tool, `moved` shows move / resize cursors; a stamp's corner
handles keep the aspect ratio unless Shift is held (`resizedKeepingAspect`); Delete key, double click edits text,
`applyStyle` (stamps: opacity only; text boxes: DA + DS), `styleOf` (text boxes: family, face
underline, strikethrough and highlight from DS), `editProperties` (`askImageStyle` for stamps,
`askStyle` with the font list + Bold / Italic / Underline / Strikethrough + Highlight + Align for text boxes), `moveSelected`/`resizeSelected`/`rotateSelected(c, ±90)`
(image stamps only, "Rotate image left/right") for programmatic use),
`FormFillTool` (outlines widgets; click toggles a check box / selects a radio export value /
opens a `PopupFactory` editor over a text field (dialog fallback when not on screen) / a
combo or multi-select list). Right clicks never reach a tool (the viewer's dispatcher shows
its Copy menu first).

**`PDFEditorPane`**: edit row `[Edit] | Undo Redo | Rotate CCW, Rotate CW (context: the current page, or the selected image stamp through `rotateInContext`; `updateButtons` swaps the icon to `RotateImageLeftIcon` / `RotateImageRightIcon` and the tooltip while an image is selected), Move… | Edit text, Form |
Highlight Underline Strikeout Note | Ink Rect Ellipse Line Arrow Text box Image | Select annot.
Delete Properties | colour, fill, opacity, width, size, font, B, I, U, S,
highlight swatch` (the colour swatch is the font colour for text boxes, tooltip and chooser title
follow `textStrip()`; the strip edits the active tool's style, or the selected annotation's; only
opacity for images; the font combo (`EditorDialogs.fontCombo`, each family rendered in its own
face), the B / I / U / S toggles, the highlight swatch (`pickHighlight`, cancel asks to remove)
and the Left / Centre / Right alignment combo only for text boxes (`textStrip()`); image rotation also through
`rotateSelectedImage(±90)`, Ctrl+Shift+L / Ctrl+Shift+R and the Annotate menu); tools are `EditTool` values installed with
`viewer.setCustomTool`, one `ButtonGroup` with a hidden "none" member cleared through
`toolDeactivated`. Turning Edit on with the toggle (and `Main.main`) activates the
Select tool, which also pans on empty space, so a fresh session can grab anything at once.
Keys: Ctrl+Z/Y, Ctrl+Shift+Z, Delete, Ctrl+Shift+H. Menus File / Edit (Undo, Redo, Edit
selected text… (Ctrl+E, works with the plain Select-text tool too), Editing enabled) /
Page (Insert, Delete, Rotate…, Move…) / Annotate (Select / move / resize and Pan only first,
then Delete selected, Properties…, Rotate selected image counter-clockwise / clockwise, then
the creation tools with a hint each, then "Insert image on this page…" and "Highlight
selected text") / Form / Help ("How to use the PDF editor…" (F1): the user guide
`src/main/resources/io/xlogistx/editor/pdf/how-to.md` (`howToMarkdown()`) in a modeless
`MDViewerPanel` window; "Version…": `versionMarkdown()` = `Main.VERSION` + PDFBox + Java versions
in a modal dialog; both skipped when headless). **Keep `how-to.md` in step with the tools**: it
is the user's only manual. API: `editSelectedText`, `replaceSelectedText(text[, alignment[,
Format]])`, `rotateSelectedImage`, `rotatePages`, `movePages`, `markSelection`, `addNote`, `addImage(page, viewRect,
File|BufferedImage)` (+ `insertImageDialog`, Annotate menu "Insert image…"), `addAnnotation`, `removeAnnotation`,
`getAnnotations`, `selectAnnotation`, `deleteSelectedAnnotation`, `applyStyleToSelection`,
`getFormFields`, `setFieldValue`, `getStyle/setStyle`, `setActiveTool/getTool`. Any editing
API call turns editing on; undo/redo clear the annotation selection first.

**Tests** (headless, run with the CLI launcher): `PDFEditModelTest`, `PDFEditorPaneTest`,
`PageOpsEditTest`, `TextEditTest` (glyph location, selection matching, replace / render /
save / undo, longer and empty replacements, refused characters), `FormFillTest` (builds an AcroForm with text / check box with Yes+Off
appearance states / combo / read-only field), `AnnotationEditTest` (markup across pages as
one step, rendered yellow pixel, note+popup, free text with non-Latin text, shapes on a 90°
page, move/resize/restyle/delete with undo), `ImageStampTest` (picture fitted and rendered,
resize keeps the same XObject and re-renders, opacity, undo, save + reload keeps the stamp
and its image, placement and aspect-locked handle math, quarter turns: red/blue picture
rendered turned, box swapped about its centre, undo, saved rotation, pushed back onto the
page), `TextFontTest` (font registry, text box in Arial Bold Italic read back and restyled
through the selection tool with undo, unknown family falls back, DS parsing; page text
rewritten in Arial Bold 14 pt red with the rest of the line keeping font / size / colour /
position, saved with the embedded font, size-only and colour-only variants, unknown family
refused; bold on the kept font (another face of the page font's family) with an underline whose
stroke lands just under the baseline, a strikethrough through the word and nowhere else, a
yellow highlight band behind the word painted before its text object with the glyphs still on
top, italic refused on a font whose family is not installed;
`HelpMenuTest` (the Help menu is last with its two items, F1 bound, the guide resource loads and
names every tool, the version text carries `Main.VERSION`); sealing: no program before, program + tag after, off the subset list; text box alignment: `Q`
written, read back and undone, the text and its underline bar render in the middle / right /
left third; the Arial parts need Arial installed, else skipped). Appearance handlers adjust `Rect` (highlight:
+ line height / 4 per side; square/circle: + border / 2; note: icon size), so tests compare
enclosure and centres.

- `PDFEdit` — one undoable change: `name()`, no-arg `apply()`/`revert()` (the edit refreshes
  the view itself through the panel primitives), `affectedPages()`, `structural()`.
- `PDFEditModel` — pure Java, EDT only: bounded undo/redo stacks (`MAX_UNDO` 100),
  `apply`/`undo`/`redo`/`peekUndo`/`peekRedo`, `Listener`. **Modified is positional**: the
  undo depth at `markSaved()` is the clean state, so undoing back to it is unmodified; when
  that depth falls off the bottom (`savedDepth = -1`) the document stays modified. A failed
  `apply` records nothing; a failed `undo` keeps the edit on the stack.
- `InsertPagesEdit(panel, source, at)` — first apply = `insertPagesDirect(source, at)` then
  captures the landed `PDPage`s; revert removes those; redo re-inserts the same objects (the
  source document may be closed after the first apply).
- `DeletePagesEdit(panel, indexes)` — first apply captures the `PDPage`s by index, then
  `removePagesDirect`; revert = `insertPagesDirect(pages, indexes, ...)` lowest index first,
  which restores the exact order.
- `PDFEditorPane` — **the embeddable component**: owns a `PDFViewerPanel` (`getViewer()`),
  re-parents the viewer's toolbar above its own edit row (`getEditToolbar()`: Edit toggle,
  Undo, Redo with `edit.name()` tooltips) and installs the `EditDelegate` that turns every
  viewer insert/delete (toolbar, dialogs, API) into the two edits above. Edits are recorded
  whether or not Edit is on; the toggle only gates Undo/Redo (buttons + Ctrl+Z / Ctrl+Y /
  Ctrl+Shift+Z, WHEN_ANCESTOR on the pane). `documentReplaced` -> `model.reset()`,
  `documentSaved` -> `markSaved()`. `createMenuBar()` = File (Open, Save, Save As, Print),
  Edit (Undo, Redo), Page (Insert, Delete); `save()` writes over a `.pdf` origin, else
  `saveAs()`. `getDocumentTitle()`, `confirmDiscard()`, change listeners. Never exits the JVM.
- `PDFMain` — the application: `VERSION` (`AppVersionDAO("PDFEditor::0.1.0")`, the `name::major.minor.nano`
  form that constructor parses) and `main [file.pdf|file.md|image]` (system look and feel, frame
  with exit-on-close, editing on, Select tool active, opens the file).
- `PDFEditorFrame` — standalone wrapper (`getVersion()` = `Main.VERSION`, `setExitOnClose` like the
  hex frame); no `main` of its own since 2026-10-16.
- Running the tests: the CLI JUnit launcher recipe (surefire is skipped in this build); the
  apps test classpath takes `xlogistx-gui-audio` from `.m2`, so run
  `mvn -o install -pl gui-audio -DskipTests` first after changing the viewer.

## Hex editor (`io.xlogistx.editor.hex`)

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

Moved here from `gui-audio` (`io.xlogistx.gui.hexeditor`) on 2026-10-15. Resources
(`about.md`, `shortcuts.md`) live in `src/main/resources/io/xlogistx/editor/hex/` and are
loaded relative to `HexEditorPane` with `getResourceAsStream`, so they must stay in the
same package path as the classes.

Rules from `gui-audio/CLAUDE.md` apply here too: no GUI work in static initializers,
`HexEditorPane` never exits the JVM, `HexEditorFrame` only calls `System.exit` when
`setExitOnClose(true)`.
