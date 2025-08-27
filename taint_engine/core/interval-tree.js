'use strict';

/**
 * Node which describes an interval.
 */
export class Node {
    constructor(start, end, left = null, right = null) {
        // The interval is stored as [start, end)
        this.interval = [start, end];
        // Max endpoint in subtree starting from this node.
        this.max = end;
        // Parent node.
        this.parentNode = null;
        // Left and right children.
        this.left = left;
        this.right = right;
    }
}

/**
 * IntervalTree maintains a collection of intervals and ensures that overlapping or
 * adjacent intervals are merged.
 */
export class IntervalTree {
    constructor() {
        this.root = null;
    }

    // ========= Private (Non-Merge-Aware) Methods =========

    // Inserts an interval without doing any merging.
    _add(interval) {
        if (!this.root) {
            this.root = new Node(interval[0], interval[1]);
            return;
        }
        addHelper(this.root, interval);
    }

    // Removes an interval by exact match using the helper routine.
    _remove(interval) {
        return this._removeHelper(interval, this.root);
    }

    _removeHelper(interval, node) {
        if (!node) return;
        // Compare using .equals for value equality.
        if (node.interval[0].equals(interval[0]) && node.interval[1].equals(interval[1])) {
            // Node found.
            if (node.left && node.right) {
                // Find replacement: choose the maximum node in the left subtree.
                let replacement = node.left;
                while (replacement.right) replacement = replacement.right;
                // Swap intervals.
                const tempInterval = node.interval;
                node.interval = replacement.interval;
                replacement.interval = tempInterval;
                // Recursively remove the duplicate from left subtree.
                this._removeHelper(replacement.interval, node.left);
            } else {
                // Node has at most one child.
                let child = node.left ? node.left : node.right;
                if (node.parentNode) {
                    if (node.parentNode.left === node) {
                        node.parentNode.left = child;
                    } else {
                        node.parentNode.right = child;
                    }
                    if (child) {
                        child.parentNode = node.parentNode;
                    }
                    // Update max values up the tree.
                    this._updateMaxUpwards(node.parentNode);
                } else {
                    // Removing the root.
                    this.root = child;
                    if (this.root) {
                        this.root.parentNode = null;
                    }
                }
            }
        } else {
            this._removeHelper(interval, node.left);
            this._removeHelper(interval, node.right);
        }
    }

    _updateMaxUpwards(node) {
        while (node) {
            let maxVal = node.interval[1];
            if (node.left && node.left.max && node.left.max.compare(maxVal) > 0) {
                maxVal = node.left.max;
            }
            if (node.right && node.right.max && node.right.max.compare(maxVal) > 0) {
                maxVal = node.right.max;
            }
            node.max = maxVal;
            node = node.parentNode;
        }
    }

    // ========= Public (Merge-Aware) Methods =========

    // Inserts an interval in a merge-aware manner.
    // This method finds any existing interval that overlaps or touches the new one,
    // merges them, and repeats until no mergeable interval remains.
    add(newInterval) {
        let interval = newInterval;
        let mergeFound = true;
        while (mergeFound) {
            mergeFound = false;
            const mergeableNode = findMergeableNode(this.root, interval);
            if (mergeableNode) {
                // Merge: union of interval and mergeableNode.interval.
                const mergedStart = interval[0].compare(mergeableNode.interval[0]) < 0 ? interval[0] : mergeableNode.interval[0];
                const mergedEnd = interval[1].compare(mergeableNode.interval[1]) > 0 ? interval[1] : mergeableNode.interval[1];
                interval = [mergedStart, mergedEnd];
                // Remove the mergeable node using the private removal.
                this._remove(mergeableNode.interval);
                mergeFound = true;
            }
        }
        // Insert the merged interval without further merging.
        this._add(interval);
    }

    // Removes an interval in a merge-aware fashion.
    // It finds all intervals that intersect the removal range, removes them,
    // and reinserts any leftover portions.
    remove(remInterval) {
        const nodesToRemove = [];
        function collectNodes(node) {
            if (!node) return;
            if (intersects(node.interval, remInterval)) {
                nodesToRemove.push(node.interval);
            }
            if (node.left && node.left.max.compare(remInterval[0]) >= 0) {
                collectNodes(node.left);
            }
            if (node.right && node.right.max.compare(remInterval[0]) >= 0) {
                collectNodes(node.right);
            }
        }
        collectNodes(this.root);
        for (const curInterval of nodesToRemove) {
            this._remove(curInterval);
            // Left remainder: [curInterval[0], remInterval[0])
            if (curInterval[0].compare(remInterval[0]) < 0) {
                const leftPart = [curInterval[0], remInterval[0]];
                if (leftPart[0].compare(leftPart[1]) < 0) {
                    this.add(leftPart);
                }
            }
            // Right remainder: [remInterval[1], curInterval[1])
            if (curInterval[1].compare(remInterval[1]) > 0) {
                const rightPart = [remInterval[1], curInterval[1]];
                if (rightPart[0].compare(rightPart[1]) < 0) {
                    this.add(rightPart);
                }
            }
        }
    }

    contains(point) {
        return contains(point, this.root);
    }

    intersects(interval) {
        return intersectsHelper(interval, this.root);
    }

    intersection(interval) {
        return intersectionHelper(interval, this.root);
    }

    height() {
        return heightHelper(this.root);
    }

    findMax(node) {
        if (!node) return null;
        let maxNode = node;
        const stack = [node];
        while (stack.length) {
            let current = stack.pop();
            if (current.interval[1].compare(maxNode.interval[1]) > 0) {
                maxNode = current;
            }
            if (current.left) stack.push(current.left);
            if (current.right) stack.push(current.right);
        }
        return maxNode;
    }

    clear() {
        this.root = null;
    }

    _prettyPrintHelper(node, prefix, isTail, childLabel = "") {
        if (!node) return "";
        const label = childLabel ? childLabel + " " : "";
        let result = prefix + (isTail ? "└── " : "├── ") + label + `[${node.interval[0]}, ${node.interval[1]}) (max: ${node.max})\n`;
        const children = [];
        if (node.left) children.push({ child: node.left, label: "L:" });
        if (node.right) children.push({ child: node.right, label: "R:" });
        for (let i = 0; i < children.length; i++) {
            result += this._prettyPrintHelper(
                children[i].child,
                prefix + (isTail ? "    " : "│   "),
                i === children.length - 1,
                children[i].label
            );
        }
        return result;
    }

    prettyPrint() {
        return this._prettyPrintHelper(this.root, "", true);
    }
}

// ========== Helper Functions ==========

function addNode(node, side, interval) {
    const child = new Node(interval[0], interval[1]);
    child.parentNode = node;
    node[side] = child;
    // Update max values up the ancestry.
    let temp = child;
    while (temp) {
        if (temp.max.compare(interval[1]) < 0) {
            temp.max = interval[1];
        }
        temp = temp.parentNode;
    }
}

function addHelper(node, interval) {
    // Insert based on the start of the interval.
    if (node.interval[0].compare(interval[0]) > 0) {
        if (node.left) {
            addHelper(node.left, interval);
        } else {
            addNode(node, "left", interval);
        }
    } else {
        if (node.right) {
            addHelper(node.right, interval);
        } else {
            addNode(node, "right", interval);
        }
    }
}

function contains(point, node) {
    if (!node) return false;
    if (node.interval[0].compare(point) <= 0 && node.interval[1].compare(point) > 0) return true;
    let result = false;
    ["left", "right"].forEach(side => {
        const temp = node[side];
        if (temp && temp.max.compare(point) > 0) {
            result = result || contains(point, temp);
        }
    });
    return result;
}

function intersects(a, b) {
    // Two intervals [a[0], a[1]) and [b[0], b[1]) intersect if a.start < b.end and b.start < a.end.
    return a[0].compare(b[1]) < 0 && b[0].compare(a[1]) < 0;
}

function intersectsHelper(interval, node) {
    if (!node) return false;
    if (intersects(node.interval, interval)) return true;
    let result = false;
    ["left", "right"].forEach(side => {
        const temp = node[side];
        if (temp && temp.max.compare(interval[0]) >= 0) {
            result = result || intersectsHelper(interval, temp);
        }
    });
    return result;
}

function intersection(a, b) {
    if (a[0].compare(b[1]) >= 0 || b[0].compare(a[1]) >= 0) return null;
    const start = a[0].compare(b[0]) >= 0 ? a[0] : b[0];
    const end = a[1].compare(b[1]) <= 0 ? a[1] : b[1];
    return [start, end];
}

function intersectionHelper(interval, node) {
    if (!node) return [];
    const result = [];
    const inter = intersection(node.interval, interval);
    if (inter) result.push(inter);
    ["left", "right"].forEach(side => {
        const temp = node[side];
        if (temp && temp.max.compare(interval[0]) >= 0) {
            result.push(...intersectionHelper(interval, temp));
        }
    });
    return result;
}

function heightHelper(node) {
    if (!node) return 0;
    return 1 + Math.max(heightHelper(node.left), heightHelper(node.right));
}

function isMergeable(interval1, interval2) {
    // Two intervals are mergeable if they overlap or touch.
    return interval1[1].compare(interval2[0]) >= 0 && interval2[1].compare(interval1[0]) >= 0;
}

function findMergeableNode(node, newInterval) {
    if (!node) return null;
    if (isMergeable(node.interval, newInterval)) return node;
    const leftResult = findMergeableNode(node.left, newInterval);
    if (leftResult) return leftResult;
    return findMergeableNode(node.right, newInterval);
}