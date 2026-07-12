/**
 * Reusable Swing GUI components and utilities for the io-xlogistx projects.
 * <p>
 * The package contains three groups of classes:
 * <ul>
 *   <li><b>Icons and helpers</b> — {@link io.xlogistx.gui.IconUtil} (vector/SVG icon
 *       library), {@link io.xlogistx.gui.GUIUtil} (static utility library: icon
 *       buttons, screen capture, clipboard, color interpolation),
 *       {@link io.xlogistx.gui.IconWidget} (base class for painted icons) and
 *       {@link io.xlogistx.gui.SelectionWindow} (full-screen drag selection
 *       overlay).</li>
 *   <li><b>Status displays</b> — {@link io.xlogistx.gui.StatusWidget} and its
 *       concrete implementations {@link io.xlogistx.gui.LedWidget} (colored LED) and
 *       {@link io.xlogistx.gui.IconStatusWidget} (icon per status), plus
 *       {@link io.xlogistx.gui.ProgressBarWidget} (percentage bar with color
 *       gradient).</li>
 *   <li><b>Data editors</b> — per-type editor widgets
 *       ({@link io.xlogistx.gui.BooleanWidget}, {@link io.xlogistx.gui.LongWidget},
 *       {@link io.xlogistx.gui.DecimalWidget}, {@link io.xlogistx.gui.EnumWidget},
 *       {@link io.xlogistx.gui.StringWidget}) wired together by
 *       {@link io.xlogistx.gui.MetaToWidget} and composed into forms by
 *       {@link io.xlogistx.gui.NVGenericMapWidget}; list/tree editors
 *       {@link io.xlogistx.gui.DynamicComboBox} and
 *       {@link io.xlogistx.gui.TreeTextWidget}.</li>
 * </ul>
 */
package io.xlogistx.gui;
