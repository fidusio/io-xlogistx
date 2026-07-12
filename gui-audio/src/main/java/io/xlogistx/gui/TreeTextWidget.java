package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * Two-pane document editor: a tree of named nodes on the left and an editable text
 * area on the right showing the selected node's content. Vertical icon buttons allow
 * adding a child node under the selection (prompting for a label), updating the
 * selected node's content from the text area, and deleting the selected node (with
 * confirmation; the root cannot be deleted).
 * <p>
 * Nodes can also be added programmatically via {@link #addEntry(String, String, String)}.
 */
public class TreeTextWidget extends JPanel {
    private final JTree tree;
    private final JTextArea textArea;
    private final DefaultTreeModel model;
    private final DefaultMutableTreeNode root;

    /**
     * Tree node payload: the label shown in the tree plus the content shown in the
     * text area.
     *
     * @param <V> content type; displayed via toString()
     */
    // Node payload: label shown in tree + content shown in text area
    static class DocNode<V> {
        String label;
        V content;

        DocNode(String label, V content) {
            this.label = label;
            this.content = content;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /**
     * Creates the widget with a single root node.
     *
     * @param mainEntryName label of the root node
     */
    public TreeTextWidget(String mainEntryName) {
        super(new BorderLayout(8, 8));

        // ---- Build model ----
        root = new DefaultMutableTreeNode(new DocNode<>(mainEntryName, ""));
        model = new DefaultTreeModel(root);

        // ---- Tree (scrollable) ----
        tree = new JTree(model);
        tree.setRootVisible(true);
        tree.setShowsRootHandles(true);
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        JScrollPane treeScroll = new JScrollPane(tree);
        treeScroll.setPreferredSize(new Dimension(260, 380));

        // ---- Text area (editable) ----
        textArea = new JTextArea(14, 40);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setEditable(true);
        JScrollPane textScroll = new JScrollPane(textArea);

        // ---- Buttons (vertical on the far left) ----
        JPanel buttons = new JPanel();
        buttons.setLayout(new BoxLayout(buttons, BoxLayout.Y_AXIS));
        int size = 24;
        JButton addBtn = GUIUtil.iconButton(new IconUtil.PlusIcon(size), true);
        JButton updateBtn = GUIUtil.iconButton(new IconUtil.UpdateIcon(size), true);
        JButton deleteBtn = GUIUtil.iconButton(new IconUtil.MinusIcon(size), true);
        addBtn.setMnemonic('A');
        updateBtn.setMnemonic('U');
        deleteBtn.setMnemonic('D');
        buttons.add(addBtn);
        buttons.add(deleteBtn);
        buttons.add(updateBtn);


        // ---- Left compound panel: [buttons | tree] ----
        JPanel leftCompound = new JPanel(new BorderLayout(8, 8));
        leftCompound.add(buttons, BorderLayout.WEST);
        leftCompound.add(treeScroll, BorderLayout.CENTER);

        // ---- Split: leftCompound | textArea ----
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftCompound, textScroll);
        split.setResizeWeight(0.45);
        add(split, BorderLayout.CENTER);

        // ---- Listeners ----
        tree.addTreeSelectionListener(this::onTreeSelectionChanged);

        addBtn.addActionListener(this::onAdd);
        updateBtn.addActionListener(this::onUpdate);
        deleteBtn.addActionListener(this::onDelete);

        // ---- Initialize selection ----
        expandAll(tree);
        TreePath initial = new TreePath(root.getPath());
        tree.setSelectionPath(initial);
        tree.scrollPathToVisible(initial);
    }

    // Selection -> load content to text area
    private void onTreeSelectionChanged(TreeSelectionEvent e) {
        DefaultMutableTreeNode node = getSelectedNode();
        if (node == null) {
            textArea.setText("");
            return;
        }
        Object uo = node.getUserObject();
        if (uo instanceof DocNode) {
            DocNode dn = (DocNode) uo;
            textArea.setText(dn.content == null ? "" : dn.content.toString());
            textArea.setCaretPosition(0);
        } else {
            textArea.setText("");
        }
    }

    // Add: create a child node under the selected node (or root), using current text area content
    private void onAdd(ActionEvent ee) {
        DefaultMutableTreeNode parent = getSelectedNode();
        if (parent == null) parent = root; // if nothing selected, add under root

        // Ask for a label
        String suggested = firstLineOr("New Node", textArea.getText()).trim();
        String label = (String) JOptionPane.showInputDialog(
                this, "New node label:", "Add Node",
                JOptionPane.PLAIN_MESSAGE, null, null, suggested);
        if (SUS.isEmpty(label)) return; // user cancelled

        DocNode dn = new DocNode(label, textArea.getText());
        DefaultMutableTreeNode child = new DefaultMutableTreeNode(dn);
        model.insertNodeInto(child, parent, parent.getChildCount());

        // Select & reveal new node
        TreePath path = new TreePath(child.getPath());
        tree.setSelectionPath(path);
        tree.scrollPathToVisible(path);
    }

    // Update: write text area content back to the selected node's payload
    private void onUpdate(ActionEvent e) {
        DefaultMutableTreeNode node = getSelectedNode();
        if (node == null) return;
        if (!(node.getUserObject() instanceof DocNode)) return;
        DocNode dn = (DocNode) node.getUserObject();
        dn.content = textArea.getText();
        // Optional: reflect first line as label when empty label
        // dn.label = (dn.label == null || dn.label.isBlank()) ? firstLineOr("Untitled", dn.content) : dn.label;

        // Tell model node changed (refresh renderer)
        model.nodeChanged(node);
        // Keep selection visible
        tree.scrollPathToVisible(new TreePath(node.getPath()));
    }

    // Delete: remove selected node (but never the root)
    private void onDelete(ActionEvent e) {
        DefaultMutableTreeNode node = getSelectedNode();
        if (node == null || node == root) return;

        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) node.getParent();
        if (parent == null) return;

        int answer = JOptionPane.showConfirmDialog(
                this, "Delete \"" + node + "\"?", "Confirm Delete",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) return;

        int parentIndex = parent.getIndex(node);
        model.removeNodeFromParent(node);

        // Choose next selection (sibling at same index, or previous, or parent)
        DefaultMutableTreeNode next = null;
        if (parent.getChildCount() > 0) {
            int idx = Math.min(parentIndex, parent.getChildCount() - 1);
            next = (DefaultMutableTreeNode) parent.getChildAt(idx);
        } else {
            next = parent;
        }
        TreePath path = new TreePath(next.getPath());
        tree.setSelectionPath(path);
        tree.scrollPathToVisible(path);
    }

    /**
     * Looks up a node's content by node label.
     *
     * @param nodeName label of the node to find
     * @param <V>      expected content type (String for nodes created through the UI
     *                 or {@link #addEntry(String, String, String)})
     * @return the node content, or null if the node is not found or has no content
     */
    @SuppressWarnings("unchecked")
    public <V> V lookup(String nodeName) {
        DefaultMutableTreeNode result = findNodeByName(nodeName);
        if (result != null) {
            Object uo = result.getUserObject();
            if (uo instanceof DocNode)
                return (V) ((DocNode<?>) uo).content;
        }
        return null;
    }

    /**
     * Adds a node under the parent with the given label (root is used when the parent
     * is not found), selects it, reveals it and loads its content into the text area.
     *
     * @param parentNodeName label of the parent node, falls back to root when not found
     * @param nodeName       label of the new node
     * @param content        content of the new node
     */
    public void addEntry(String parentNodeName, String nodeName, String content) {
        DefaultMutableTreeNode parent = findNodeByName(parentNodeName);
        if (parent == null) {
            parent = root; // fallback to root
        }

        DocNode<String> dn = new DocNode<String>(nodeName, content);
        DefaultMutableTreeNode child = new DefaultMutableTreeNode(dn);
        model.insertNodeInto(child, parent, parent.getChildCount());

        TreePath path = new TreePath(child.getPath());
        tree.setSelectionPath(path);
        tree.scrollPathToVisible(path);

        textArea.setText(content);
        textArea.setCaretPosition(0);
    }

    private DefaultMutableTreeNode findNodeByName(String name) {
        return findNodeRecursive(root, name);
    }

    private DefaultMutableTreeNode findNodeRecursive(DefaultMutableTreeNode current, String name) {
        Object uo = current.getUserObject();
        if (uo instanceof DocNode) {
            DocNode dn = (DocNode) uo;
            if (dn.label.equals(name)) {
                return current;
            }
        }
        for (int i = 0; i < current.getChildCount(); i++) {
            DefaultMutableTreeNode found = findNodeRecursive(
                    (DefaultMutableTreeNode) current.getChildAt(i), name);
            if (found != null) return found;
        }
        return null;
    }

    private DefaultMutableTreeNode getSelectedNode() {
        TreePath path = tree.getSelectionPath();
        if (path == null) return null;
        return (DefaultMutableTreeNode) path.getLastPathComponent();
    }

    /**
     * Returns the current text area content (which may contain unsaved edits not yet
     * applied to the selected node).
     *
     * @return the text area content
     */
    public String getContent() {
        return textArea.getText();
    }

    private static void expandAll(JTree tree) {
        for (int i = 0; i < tree.getRowCount(); i++) tree.expandRow(i);
    }

    private static String firstLineOr(String fallback, String text) {
        if (text == null || text.trim().isEmpty()) return fallback;
        String[] lines = text.trim().split("\\R", 2); // Java 8 safe
        String line = lines.length > 0 ? lines[0] : fallback;
        return line.length() > 40 ? line.substring(0, 40) + "…" : line;
    }

}


