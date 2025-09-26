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

public class TreeTextWidget extends JPanel {
    private final JTree tree;
    private final JTextArea textArea;
    private final DefaultTreeModel model;
    private final DefaultMutableTreeNode root;

    // Node payload: label shown in tree + content shown in text area
    static class DocNode<V> {
        String label;
        V content;
        DocNode(String label, V content) { this.label = label; this.content = content; }
        @Override public String toString() { return label; }
    }

    public TreeTextWidget(String mainEntryName) {
        super(new BorderLayout(8, 8));

        // ---- Build model ----
        root = new DefaultMutableTreeNode(new DocNode(mainEntryName, ""));
//        DefaultMutableTreeNode intro = new DefaultMutableTreeNode(new DocNode(
//                "Introduction", "This is the introduction text."));
//        DefaultMutableTreeNode usage = new DefaultMutableTreeNode(new DocNode(
//                "Usage", "Steps to use the tool:\n1) Do this\n2) Do that\n3) Profit"));
//        DefaultMutableTreeNode api = new DefaultMutableTreeNode(new DocNode("API", ""));
//        api.add(new DefaultMutableTreeNode(new DocNode("Auth", "Auth API details here.")));
//        api.add(new DefaultMutableTreeNode(new DocNode("Data", "Data API notes go here.")));
//        root.add(intro);
//        root.add(usage);
//        root.add(api);
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
        JButton addBtn = GUIUtil.iconButton(new GUIUtil.PlusIcon(size));
        JButton updateBtn = GUIUtil.iconButton(new GUIUtil.UpdateIcon(size));
        JButton deleteBtn = GUIUtil.iconButton(new GUIUtil.MinusIcon(size));
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
        if (node == null) { textArea.setText(""); return; }
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

//    public void addEntry(String nodeName, String content) {
//        DocNode dn = new DocNode(nodeName, content);
//        DefaultMutableTreeNode child = new DefaultMutableTreeNode(dn);
//        model.insertNodeInto(child, root, root.getChildCount());
//
//        TreePath path = new TreePath(child.getPath());
//        tree.setSelectionPath(path);
//        tree.scrollPathToVisible(path);
//
//        textArea.setText(content);
//        textArea.setCaretPosition(0);
//    }

    public<V> V lookup(String nodeName)
    {
        DefaultMutableTreeNode result = findNodeByName(nodeName);
        if(result != null)
        {
            result.getUserObject();
        }

        return null;
    }

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

    public String getContent()
    {
        return textArea.getText();
    }

//    private static String firstLineOr(String fallback, String text) {
//        if (SUS.isEmpty(text)) return fallback;
//        String line = text.trim().lines().findFirst().orElse(fallback);
//        // Keep node labels short-ish
//        return line.length() > 40 ? line.substring(0, 40) + "…" : line;
//    }

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


