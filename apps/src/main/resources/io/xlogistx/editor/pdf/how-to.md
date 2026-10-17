# PDF Editor: how to use it

The window has two toolbar rows. The **top row** is the viewer: open, save, print, insert and
delete pages, pan / select text / zoom tools, page navigation, zoom and search. The **second
row** is the editor: it starts with the **Edit** toggle (pencil). Everything on that row is
greyed out until Edit is on. Turning Edit on also activates the **Select / move / resize** tool,
so you can click anything you have added and move it right away.

Every change is undoable: **Ctrl+Z** undoes, **Ctrl+Y** (or Ctrl+Shift+Z) redoes. Undo and redo
drop the current selection first. Saving over the open file clears the undo history.

## 1. Pages

| What | Where | Notes |
|------|-------|-------|
| Insert pages | top row **Insert**, or Page ▸ Insert… | Takes a PDF, a Markdown file or an image; choose beginning / end / after page n. |
| Delete pages | top row **Delete**, or Page ▸ Delete… | `current`, `3`, `5-8` or a comma separated list. The document cannot be emptied. |
| Rotate pages | second row rotate buttons (current page; with an image selected they rotate the image instead), or Page ▸ Rotate clockwise / counter-clockwise… | Quarter turns. |
| Move pages | second row **Move pages…**, or Page ▸ Move… | Same page selection, then beginning / end / after page n. |

## 2. The tools on the second row

Only one tool is active at a time. Pick it with its button, or in the **Annotate** menu where
every tool has a hint. Picking **Pan** or **Select text** in the top row switches the editing
tool off.

### Select / move / resize (the cursor over a dashed box, at the right end)

- **Click** an annotation or picture to select it: a dashed blue frame with eight handles.
- **Drag inside** the frame to move it. **Drag a handle** to resize (for pictures the corner
  handles keep the proportions; hold **Shift** while dragging to stretch freely). Lines have
  two end handles. Ink and text markup can be moved, not resized.
- **Delete** (or Backspace) removes the selection. **Double click** a note or a text box to
  edit its text. The **Properties** button (the "i") opens the full style dialog.
- The style strip at the end of the row shows the selected annotation's colours and sizes;
  changing a value there changes the annotation at once.
- A drag on empty page space **pans** the page, so you never need to leave this tool to scroll.

### Edit text (the T with a pencil): rewrite words that are already on the page

- **Double click a word**, or drag over text and press **Enter** (or **Ctrl+E**, which also
  works with the plain Select-text tool of the top row). The selection must stay on one page.
- The dialog shows the text and:
  - **Align**: where the new text sits in the room the old text took (nothing reflows): keep
    the start, the centre, or the end.
  - **Font**: "keep the current font" uses the page's own font, so only characters that font
    already shows in the document can be typed. Pick any installed font to type anything.
  - **Bold / Italic**: pre-ticked with the word's current face. With the current font kept,
    the editor loads the matching face of that font's family, which must be installed.
  - **Underline / Strikethrough**: lines under / through the new text only.
  - **Size** and **Font colour**: start at the word's own values; leave them to keep them.
  - **Highlight**: a colour band behind the new text.
- The rest of the line keeps its font, size, colour and position. A replacement wider than the
  old word overlaps what follows: shorten it, use a smaller size, or make room with alignment.
- Text drawn by embedded forms or images cannot be edited this way.

### Fill form fields (the field with a caret)

Fillable fields get a faint outline. Click a text field to type into it, a check box to toggle
it, a radio button to pick it, a list or combo to choose. Enter or clicking elsewhere commits,
Esc cancels. Read-only and signature fields are not changed. Form ▸ Fill form fields does the
same.

### Highlight, Underline, Strikeout (text markup)

Drag over page text with the tool, release, done. With any tool, **Ctrl+Shift+H** (Annotate ▸
Highlight selected text) highlights the current text selection. The markup colour is the
strip's colour swatch while the tool is active.

### Note (speech bubble)

Click where the note icon should go and type the text. Double click an existing note (with
the Select tool) to edit it. Other viewers show the text in a popup.

### Ink, Rectangle, Ellipse, Line, Arrow

Drag to draw. The strip sets the **colour**, the **fill** (rectangle, ellipse, arrow head and
line interior; "none" is transparent), the **opacity** and the **width** before you draw, and
of the selected shape afterwards. Very small drags (under 3 pt) are ignored.

### Text box (T in a box)

- Drag a box (or just click for a 160 × 40 pt box) and type the text. Text wraps inside the
  box; a word too long for the box is broken by characters.
- The strip, and the Properties dialog, give you: **font colour**, **fill** (box background),
  **opacity**, **width** (border, 0 = none), **size**, the **font** list (the bundled Roboto,
  then every font installed on this machine, each shown in its own face), **B / I / U / S**
  (bold, italic, underline, strikethrough), the **highlight** swatch (a colour band behind the
  text, not the box) and **Left / Centre / Right** alignment.
- Values set while the Text box tool is active are remembered for the next box. With a text
  box selected they change that box.
- Any character the chosen font has can be typed; a missing glyph shows as `?`.

### Image (the framed picture): put a picture on the page

- Drag a box (or click) and pick a PNG, JPEG, GIF, BMP or TIFF file. The picture is fitted
  into the box keeping its proportions; a plain click places it at its own size. Annotate ▸
  Insert image on this page… places it at the top-left margin.
- The picture is selected at once, so you can **move** it, **resize** it by the handles, and
  **rotate** it a quarter turn with the two rotate buttons next to Undo / Redo: while an image
  is selected they show a framed picture instead of a page and rotate the image, not the page
  (**Ctrl+Shift+L** counter-clockwise, **Ctrl+Shift+R** clockwise). The strip offers its
  **opacity**.
- Pressing on an existing picture while the Image tool is active grabs that picture instead of
  starting a new one.

## 3. Menus

- **File**: Open, Save, Save As…, Print…, Exit (standalone window).
- **Edit**: Undo, Redo, Edit selected text…, Editing enabled.
- **Page**: Insert…, Delete…, Rotate…, Move….
- **Annotate**: the Select tool and Pan first, then Delete selected, Properties…, Rotate
  selected image, the creation tools with a hint each, Insert image on this page…, Highlight
  selected text.
- **Form**: Fill form fields.
- **Help**: this guide and the version.

## 4. Keyboard

| Keys | Action |
|------|--------|
| Ctrl+O / Ctrl+S / Ctrl+Shift+S / Ctrl+P | Open / Save / Save As / Print |
| Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z | Undo / Redo |
| Delete, Backspace | Delete the selected annotation |
| Ctrl+E, Enter (Edit text tool) | Edit the selected page text |
| Ctrl+Shift+H | Highlight the selected text |
| Ctrl+Shift+L / Ctrl+Shift+R | Rotate the selected image |
| Esc | Cancel the current drag, clear the selection, then back to Pan |
| F1 | This guide |
| PgUp / PgDn, Ctrl+PgUp / Ctrl+PgDn, Ctrl+Home / Ctrl+End | Scroll a screen, previous / next page, first / last page |
| Ctrl + / Ctrl −, Ctrl+0, Ctrl+wheel | Zoom in / out, fit width, zoom around the pointer |
| Ctrl+A / Ctrl+C | Select all text / copy the selection |
| F3 / Shift+F3 | Next / previous search match |

## 5. Saving and what other programs see

Everything you add is written as standard PDF annotations and page content, so Acrobat, Edge,
Chrome and the others show and print it. Rewritten text, underlines, strikethroughs and
highlights of page text become part of the page itself; notes, markup, shapes, text boxes and
pictures stay separate annotations that other editors can still move or delete. Fonts you
pick are embedded (only the characters used), so the file looks the same everywhere.

Saving **over the file you opened** closes and reloads it, which keeps the page but clears
the selection and the undo history. **Save As…** to a new file keeps the session as it is.

## 6. Limits

- No reflow: edited page text never pushes the following text along.
- Only TrueType fonts can be embedded; a font the system lists but cannot be read as one is
  refused with a message, and a text box falls back to Roboto.
- Images are placed as stamps: they can be moved, resized, rotated in quarter turns and
  deleted, not cropped or edited.
- Page content inside embedded forms (and scanned pages without a text layer) has no
  editable text; add a text box over it instead.
