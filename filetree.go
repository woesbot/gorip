package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// TreeNode represents a node in the file tree
type TreeNode struct {
	Name     string
	IsDir    bool
	Entry    *FSCEntry
	Children map[string]*TreeNode
}

// FileTree represents the entire file tree
type FileTree struct {
	Root *TreeNode
}

// NewFileTree creates a new file tree with a root node
func NewFileTree() *FileTree {
	return &FileTree{
		Root: &TreeNode{
			Name:     "/",
			IsDir:    true,
			Entry:    &FSCEntry{},
			Children: make(map[string]*TreeNode),
		},
	}
}

// Insert inserts a new file or directory into the file tree
func (ft *FileTree) Insert(f *FSCEntry) {
	components := strings.Split(f.Name, "/")
	currentNode := ft.Root

	for _, component := range components {
		if component == "" {
			continue
		}
		// check if the component already exists in the current node's children
		childNode, exists := currentNode.Children[component]
		if !exists {
			// if it doesn't exist, create a new node and add it to the current node's children
			childNode = &TreeNode{
				Name:     component,
				Entry:    f,
				IsDir:    f.IsDir,
				Children: make(map[string]*TreeNode),
			}
			currentNode.Children[component] = childNode
		}

		currentNode = childNode
	}
}

// Output the tree
func PrintTree(node *TreeNode, indent string, writer io.Writer) {
	fmt.Fprintf(writer, indent+node.Name)

	if node.IsDir && node.Name != "/" {
		fmt.Fprintln(writer, "/")
	} else {
		fmt.Fprintln(writer)
	}

	for _, child := range node.Children {
		PrintTree(child, indent+" ", writer)
	}
}

// Output the tree sorted in lexicographical order
func PrintTreeSorted(node *TreeNode, indent string, writer io.Writer) {
	fmt.Fprintf(writer, "%s%s", indent, node.Name)

	if node.IsDir && node.Name != "/" {
		fmt.Fprintln(writer, "/")
	} else {
		fmt.Fprintln(writer)
	}

	var keys []string
	for key := range node.Children {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		child := node.Children[key]
		PrintTreeSorted(child, indent+" ", writer)
	}
}
