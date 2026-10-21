# PDF Editor: how to use it

The window has two toolbar rows. The **top row** is the viewer: open, save, print, insert and
delete pages, the **page thumbnails** toggle, pan / select text / zoom tools, page navigation,
zoom, search and, at the right end, the **control text size** ("Aa" and a number: the size of
the text in menus, buttons and labels, for a bigger or smaller interface). The **second
row** is the editor: it starts with the **Edit** toggle (pencil). Everything on that row is
greyed out until Edit is on. Turning Edit on also activates the **Select / move / resize** tool,
so you can click anything you have added and move it right away.

The second row only shows what you can use right now: after the page buttons and the tools
come **Delete** and **Properties**, which appear while something is selected, and the **style
strip** (colours, opacity, width, font...), which appears while a tool that has a style is
active or a styled annotation is selected, with only the controls that apply (a picture has
just opacity, a text box also the font controls).

The **status line** at the bottom says what the active tool does on the left and what is
selected on the right (its kind, size, rotation and page).

Every tool has a **letter key**, shown in its tooltip and in the Annotate menu: **V** Select,
**E** Edit text, **F** Form, **H** Highlight, **U** Underline, **S** Strikeout, **N** Note,
**P** Pen (ink), **R** Rectangle, **O** Ellipse, **L** Line, **A** Arrow, **T** Text box,
**I** Image. They work while the pages have the focus (click the page first); typing in the
page, zoom or search fields never switches tools. A letter also turns Edit on.

**Right click** anything: on an annotation or picture the menu selects it and offers Edit
text (notes and text boxes), Rotate (pictures), Cut, Copy, Duplicate, Properties and Delete;
on selected page text it offers Edit, Highlight, Underline and Strike out; on empty space
**Paste here**; Copy, Select all and Clear selection are always there.

**Tabs.** Each document has its own tab above the toolbars, with its own undo history,
selection and status line. Opening a file while the current tab already shows one (Open, the
toolbar button, Open Recent or a dropped file with the Open choice) puts it in a **new tab**;
an empty tab is filled instead. **Ctrl+T** adds an empty tab, **Ctrl+W** (or the x on the tab, or
a middle click) closes the current one after asking about unsaved changes, **Ctrl+Tab** /
**Ctrl+Shift+Tab** go to the next / previous tab, **Alt+1** to **Alt+9** jump to a tab, and the
**Tabs** menu lists every open document. Closing the last tab leaves an empty one; closing the
window asks about every tab with unsaved changes. Starting the editor with several files opens
each in its own tab.

**Copy and paste.** Select a picture, text box, note, shape or any other annotation and press
**Ctrl+C** (or **Ctrl+X** to cut it). **Ctrl+V** puts a copy under the mouse pointer, on any
page, in **another tab's document** (switch tabs and paste; a picture is copied into that file)
or in another file opened later; when the pointer is not over the pages it lands in
the middle of the view. Pasting again without moving the pointer puts each copy 10 pt right
and below the previous one, so they do not pile up. The copy is selected at once, so the arrow
keys or a drag place it exactly. **Ctrl+D** duplicates the selection 10 pt right and down without touching the
clipboard. The clipboard also works with other programs: a copied picture or note text can be
pasted elsewhere, and text or a picture copied from another program is pasted as a text box
(in the current text style) or an image. With nothing selected, Ctrl+C copies the selected
page text as before.

Every change is undoable: **Ctrl+Z** undoes, **Ctrl+Y** (or Ctrl+Shift+Z) redoes. Undo and redo
drop the current selection first. Saving keeps the history, so you can still undo afterwards.

## 1. Pages

The **thumbnail sidebar** (the toggle after Delete on the top row, or View ▸ Page thumbnails)
shows every page as a small picture with its number, the current page framed in blue. **Click**
a thumbnail to go to that page. **Drag** a thumbnail up or down and drop it where the blue line
is to move the page there (undoable like every other change).

| What | Where | Notes |
|------|-------|-------|
| Insert pages | top row **Insert**, or Page ▸ Insert… | Takes a PDF, a Markdown file or an image; choose beginning / end / after page n. |
| Delete pages | top row **Delete**, or Page ▸ Delete… | `current`, `3`, `5-8` or a comma separated list. The document cannot be emptied. |
| Rotate pages | second row rotate buttons (current page; with an image selected they rotate the image instead), or Page ▸ Rotate clockwise / counter-clockwise… | Quarter turns. |
| Move pages | drag a thumbnail in the sidebar; second row **Move pages…**, or Page ▸ Move… | The dialog takes the same page selection, then beginning / end / after page n. |

## 2. The tools on the second row

Only one tool is active at a time. Pick it with its button, or in the **Annotate** menu where
every tool has a hint. Picking **Pan** or **Select text** in the top row switches the editing
tool off.

### Select / move / resize (the cursor over a dashed box, at the right end)

- **Click** an annotation or picture to select it: a dashed blue frame with eight handles.
- **Drag inside** the frame to move it. **Drag a handle** to resize (for pictures the corner
  handles keep the proportions; hold **Shift** while dragging to stretch freely). Lines have
  two end handles. Ink and text markup can be moved, not resized.
- **Arrow keys** nudge the selection by 1 pt, with **Shift** by 10 pt; a quick run of nudges is
  one undo step. Without a selection the arrows scroll as usual.
- **Ctrl+C / Ctrl+X** copy or cut the selection, **Ctrl+V** pastes it under the pointer (on any
  page), **Ctrl+D** duplicates it next to the original; see the start of this guide.
- **Delete** (or Backspace) removes the selection. **Double click** a text box to type into it
  on the page (Ctrl+Enter or a click elsewhere finishes, Esc cancels), a note to edit its text
  in a dialog. The **Properties** button (the "i") opens the full style dialog.
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
it, a radio button to pick it, a list or combo to choose. What you type into a text field is
kept however you leave it: **Enter** (Ctrl+Enter in a multi-line field), a click anywhere else,
switching tools, undo or save all write it into the field. Only **Esc** drops it. Each filled
field is one undo step. Read-only and signature fields are not changed. Form ▸ Fill form fields
does the same as the tool button.

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

- Drag a box (or just click for a 160 × 40 pt box) and **type straight into it on the page**.
  Enter starts a new line; **Ctrl+Enter**, or a click anywhere else, finishes the box; **Esc**
  throws it away. An empty box is not added. Text wraps inside the box; a word too long for
  the box is broken by characters. Switching tools while typing keeps the text.
- To change the text later, **double click** the box with the Select tool (or right click ▸
  Edit the text) and type; the same keys finish or cancel, and the change is one undo step.
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

- **File**: Open, Open Recent (the last ten files, Clear list), Save, Save As…, Document
  password…, Print…, Exit (standalone window).
- **Edit**: Undo, Redo, Cut annotation, Copy, Paste, Duplicate annotation, Edit selected
  text…, Editing enabled.
- **View**: Page thumbnails; Control text size ▸ Larger (Ctrl+Alt+=), Smaller (Ctrl+Alt+-),
  Reset (Ctrl+Alt+0).
- **Page**: Insert…, Delete…, Rotate…, Move….
- **Annotate**: the Select tool and Pan first, then Delete selected, Properties…, Rotate
  selected image, the creation tools with a hint and their letter key each, Insert image on
  this page…, Highlight selected text.
- **Right-click menu** over the pages: see the start of this guide.
- **Form**: Fill form fields.
- **Tabs**: New tab (Ctrl+T), Close tab (Ctrl+W), Close other tabs, Next / Previous tab
  (Ctrl+Tab / Ctrl+Shift+Tab), then one entry per open document (Alt+1 to Alt+9).
- **Help**: this guide and the version.

## 4. Keyboard

| Keys | Action |
|------|--------|
| Ctrl+O / Ctrl+S / Ctrl+Shift+S / Ctrl+P | Open (in a new tab when this one shows a document) / Save / Save As / Print |
| Ctrl+T / Ctrl+W | New tab / Close tab |
| Ctrl+Tab / Ctrl+Shift+Tab, Alt+1 to Alt+9 | Next / previous tab, go to tab n |
| Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z | Undo / Redo |
| Delete, Backspace | Delete the selected annotation |
| Ctrl+X / Ctrl+C / Ctrl+V / Ctrl+D | Cut / copy the selected annotation (else copy the selected text) / paste under the pointer / duplicate |
| Ctrl+E, Enter (Edit text tool) | Edit the selected page text |
| Ctrl+Enter / Esc (typing in a text box) | Finish the text box / drop the typing |
| Enter / Esc (typing in a form field) | Write the value into the field (a click elsewhere does too) / drop the typing |
| Ctrl+Shift+H | Highlight the selected text |
| Ctrl+Shift+L / Ctrl+Shift+R | Rotate the selected image |
| V, E, F, H, U, S, N, P, R, O, L, A, T, I | Pick a tool (see the tooltips; pages must have the focus) |
| Arrow keys, Shift+arrows | Nudge the selected annotation by 1 pt / 10 pt |
| Esc | Cancel the current drag, clear the selection, then back to Pan |
| F1 | This guide |
| PgUp / PgDn, Ctrl+PgUp / Ctrl+PgDn, Ctrl+Home / Ctrl+End | Scroll a screen, previous / next page, first / last page |
| Ctrl + / Ctrl −, Ctrl+0, Ctrl+wheel | Zoom in / out, fit width, zoom around the pointer |
| Ctrl+A | Select all text |
| F3 / Shift+F3 | Next / previous search match |

## 5. Saving and what other programs see

Everything you add is written as standard PDF annotations and page content, so Acrobat, Edge,
Chrome and the others show and print it. Rewritten text, underlines, strikethroughs and
highlights of page text become part of the page itself; notes, markup, shapes, text boxes and
pictures stay separate annotations that other editors can still move or delete. Fonts you
pick are embedded (only the characters used), so the file looks the same everywhere.

Saving, **over the file you opened** or with **Save As…** to a new file, keeps the session as
it is: the page, the selection and the undo history. The file is written next to its final
place first and then moved over it, so an interrupted save never leaves a half-written PDF.

### Passwords

- **Opening a protected file** asks for its password (as many times as it takes; Cancel leaves
  the file closed). The same goes for a protected file you insert or drop. Once open, the file
  behaves like any other, and saving it keeps its password and its permissions, so it stays
  protected on disk. The status line shows "Protected: …" on the right while nothing is
  selected.
- **File ▸ Document password…** sets, changes or removes the protection of the open document:
  the **password to open** (typed twice), an optional **owner password** (the one that lets
  someone change the protection later; empty = the open password) and what a reader may do:
  **print**, **copy** text and pictures, **make changes**. Leave both passwords empty and
  allow everything to remove the protection. The change is an undo step like any other and
  takes effect when you save; the pages on screen are not touched.
- Files are encrypted with AES-256. Other readers ask for the open password and respect the
  permissions; the editor itself shows a protected file in full once it is open.

## 6. Drag and drop, recent files, what is remembered

- **Drop files on the window.** With nothing open in the current tab, a dropped PDF, Markdown
  file or image is opened there (several files at once are joined into one new document, in the
  order dropped). With a document open, a dialog asks whether to open the files in a new tab,
  insert their pages after the current page or at the end; inserted pages are undoable. A single **picture dropped on a
  page while Edit is on** is placed there as an image stamp, selected, ready to move or resize.
- **Open Recent** in the File menu lists the last ten files opened or saved; a file that has
  gone is dropped from the list when chosen. **Clear list** empties it.
- Between runs the editor remembers the window size and position, whether the thumbnail
  sidebar is shown, the zoom, the control text size, the recent files and the folder the file
  dialogs start in.

## 7. Limits

- No reflow: edited page text never pushes the following text along.
- Only TrueType fonts can be embedded; a font the system lists but cannot be read as one is
  refused with a message, and a text box falls back to Roboto.
- Images are placed as stamps: they can be moved, resized, rotated in quarter turns and
  deleted, not cropped or edited.
- Page content inside embedded forms (and scanned pages without a text layer) has no
  editable text; add a text box over it instead.
- A protected file opened with its open password is saved with that password as its owner
  password too: the original owner password is not in the file in a recoverable form. Open the
  file with the owner password to keep it.
