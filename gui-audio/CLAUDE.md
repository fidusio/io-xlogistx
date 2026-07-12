# Claude Code Instructions for gui-audio

Swing GUI widgets and (eventually) audio utilities for the io-xlogistx projects.
Java package: `io.xlogistx.gui` (see `package-info.java` for the class map).

## Architecture

The package has three groups:

1. **Icons & helpers**
   - `IconUtil` — the icon library. All icons are SVG-based (`PlusIcon`, `MinusIcon`,
     `CancelIcon`, `SaveIcon`, `UpdateIcon`, `EditIcon`, `DeleteIcon`, `BackIcon`,
     `NextIcon`, `RollbackIcon`, `VisibleIcon`, `InvisibleIcon`, `CopyIcon`, `SearchIcon`,
     `RefreshIcon`, generic `SVGIcon` + `svgIcon(...)` factories). All extend `IconWidget`; the SVG-based
     ones share the `SVGIconWidget` base. **SVG icon constructor contract**:
     `XxxIcon(int size)` renders the svg with its own colors and does NOT touch the host
     component's background; `XxxIcon(int size, Color color)` tints the glyph and paints
     the icon's background color on the host component.
   - `GUIUtil` — static helpers only: `iconButton(...)` factories, screen capture
     (`captureSelectedArea()`), clipboard, panels/scroll panes, color interpolation
     (`colorToRatio`, `interpolateColors`).
   - `SelectionWindow` — full-screen translucent drag-selection overlay used by
     `GUIUtil.captureSelectedArea()` (Lock/Condition handshake, predicate-loop guarded).
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
  `update`, `copy`, `search`, `refresh`). All are Feather-style: 24x24 viewBox,
  `fill="none"`, `stroke="#5A5A5A"`, stroke-width 2, round caps/joins — match this style
  when adding new ones. Each `XxxIcon` class maps to the same-named svg
  (`PlusIcon`→`plus.svg`, ...), except: `EditIcon`→`edit.svg` is a pencil,
  `DeleteIcon`→`delete.svg` is a trash can, `UpdateIcon`→`update.svg` is two chasing
  arrows (sync), `RefreshIcon`→`refresh.svg` is a single clockwise arrow,
  `RollbackIcon`→`rollback.svg` is its counterclockwise mirror. Every svg has a
  dedicated class; one-off svgs can be loaded via `IconUtil.svgIcon(...)`.

## Dependencies

- **JSVG** (`com.github.weisj:jsvg`) — SVG rendering. Do not add batik or other SVG libs.
- `common` module (`NVColor`), zoxweb (`NVGenericMap`, `MappedObject`, `SUS`, `ServerUtil`).

## Demos / manual testing

Interactive demos (main methods) in `src/test/java/io/xlogistx/gui/test/`:
- `IconWidgetDemo` — all icons as labels and buttons
- `StateIconDemo` — status widgets
- `CaptureSelectedAreaDemo` — screen-area selection + screenshot (shows the intended
  off-EDT usage of `captureSelectedArea()`)

Build: `mvn clean install -pl gui-audio -am` (from repo root). No headless-safe unit tests
exist for the Swing classes; verification is via the demos.

## Known limitations (accepted, not bugs)

- `SelectionWindow` covers the primary monitor only (`Toolkit.getScreenSize()`).
- No ESC/cancel for a selection in progress (a JWindow without a visible owner cannot get
  key focus; would need an AWTEventListener if ever required).
- A click without drag yields an empty (0x0) selection rectangle — callers must handle it
  (see `CaptureSelectedAreaDemo`).
- `paintIcon` implementations call `c.setBackground(...)` — required by the macOS swap
  behavior; only effective on opaque components.
