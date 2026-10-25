package io.xlogistx.gui;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A directory picker as one field: the chosen path in a read-only text field and a
 * <b>Choose…</b> button that opens a directories-only {@link JFileChooser}. The chooser opens on
 * the current directory, else on {@link #startDirectory(Supplier)}'s answer, else on the user's
 * home. It is shown as a <em>save</em> dialog so a directory that does not exist yet can be typed
 * and returned, which is how a first-run location is named.
 * <p>
 * {@link #setDirectory(File)} sets the value silently; only a choice made through the button
 * reaches the {@link #onChange(Consumer)} listeners.
 */
public class DirectoryField extends JPanel {

    private final JTextField path = new JTextField();
    private final JButton choose = new JButton("Choose…", new IconUtil.FolderIcon(16));
    private final JFileChooser chooser = new JFileChooser();
    private final List<Consumer<File>> listeners = new ArrayList<>();
    private File directory;
    private Supplier<File> startDirectory;

    public DirectoryField() {
        super(new BorderLayout(6, 0));
        setOpaque(false);
        path.setEditable(false);
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Choose a directory");
        choose.addActionListener(e -> browse());
        add(path, BorderLayout.CENTER);
        add(choose, BorderLayout.EAST);
    }

    /** The chooser's window title. */
    public DirectoryField dialogTitle(String title) {
        chooser.setDialogTitle(title);
        return this;
    }

    /** Placeholder text shown while no directory is chosen (FlatLaf). */
    public DirectoryField placeholder(String text) {
        path.putClientProperty("JTextField.placeholderText", text);
        return this;
    }

    /** Where the chooser opens when no directory is set yet; null answers fall back to the home directory. */
    public DirectoryField startDirectory(Supplier<File> supplier) {
        this.startDirectory = supplier;
        return this;
    }

    /** Sets the value without notifying listeners. */
    public void setDirectory(File directory) {
        this.directory = directory;
        path.setText(directory != null ? directory.getAbsolutePath() : "");
    }

    /** The chosen directory, or null. */
    public File getDirectory() {
        return directory;
    }

    /** Called with the new directory after every choice made through the button. */
    public void onChange(Consumer<File> listener) {
        listeners.add(listener);
    }

    public JTextField getPathField() {
        return path;
    }

    public JButton getChooseButton() {
        return choose;
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        choose.setEnabled(enabled);
    }

    private void browse() {
        File start = directory;
        if (start == null && startDirectory != null) start = startDirectory.get();
        if (start == null) start = new File(System.getProperty("user.home"));
        chooser.setCurrentDirectory(start);
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            if (selected == null) return;
            setDirectory(selected);
            for (Consumer<File> l : listeners) l.accept(selected);
        }
    }
}
