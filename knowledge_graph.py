# knowledge_graph.py
import networkx as nx
from collections import defaultdict


class ComplianceKnowledgeGraph:
    """Builds a knowledge graph linking audit results, violations,
    NIST controls, CIS benchmarks, and config lines."""

    def __init__(self, audit):
        self.audit = audit
        self.G = nx.DiGraph()

    def build(self):
        audit = self.audit
        filename = audit.get('filename', 'unknown')
        vendor = audit.get('vendor', 'UNKNOWN')
        violations = audit.get('violations', [])
        passed = audit.get('passed_checks', [])

        # 1. Root node — the file
        file_id = "file::" + filename
        self.G.add_node(file_id, label=filename, type='file', size=60)

        # 2. Vendor node
        vendor_id = "vendor::" + vendor
        self.G.add_node(vendor_id, label=vendor, type='vendor', size=45)
        self.G.add_edge(file_id, vendor_id, relation='detected_as')

        # 3. Violation nodes + NIST/CIS mapping
        nist_seen = set()
        cis_seen = set()

        for v in violations:
            rule = v.get('rule', 'unknown')
            desc = v.get('description', rule)
            severity = v.get('severity', 'LOW')
            viol_id = "violation::" + rule

            self.G.add_node(
                viol_id,
                label=desc[:40],
                type='violation',
                severity=severity,
                size=30
            )
            self.G.add_edge(vendor_id, viol_id, relation='produced')

            # Link to config line
            line_number = v.get('line_number')
            if line_number:
                line_id = "line::" + str(line_number)
                if line_id not in self.G:
                    self.G.add_node(
                        line_id,
                        label="L" + str(line_number),
                        type='line',
                        size=18
                    )
                self.G.add_edge(viol_id, line_id, relation='at_line')

            # Link to NIST control
            nist_control = v.get('nist_control', '')
            if nist_control:
                nist_id = "nist::" + nist_control
                if nist_id not in nist_seen:
                    self.G.add_node(
                        nist_id,
                        label=nist_control,
                        type='nist',
                        size=35
                    )
                    nist_seen.add(nist_id)
                self.G.add_edge(viol_id, nist_id, relation='violates')

            # Link to CIS benchmark
            cis_benchmark = v.get('cis_benchmark', '')
            if cis_benchmark:
                cis_id = "cis::" + cis_benchmark
                if cis_id not in cis_seen:
                    self.G.add_node(
                        cis_id,
                        label=cis_benchmark,
                        type='cis',
                        size=35
                    )
                    cis_seen.add(cis_id)
                self.G.add_edge(viol_id, cis_id, relation='violates')

        return self.G

    def to_cytoscape_json(self):
        """Export graph to Cytoscape.js format"""
        nodes = []
        edges = []

        for node_id, data in self.G.nodes(data=True):
            nodes.append({
                'data': {
                    'id': str(node_id),
                    'label': str(data.get('label', node_id)),
                    'type': str(data.get('type', 'default')),
                    'severity': str(data.get('severity', '')),
                    'size': int(data.get('size', 30))
                }
            })

        for src, dst, data in self.G.edges(data=True):
            edges.append({
                'data': {
                    'id': str(src) + "->" + str(dst),
                    'source': str(src),
                    'target': str(dst),
                    'relation': str(data.get('relation', 'related'))
                }
            })

        return {'nodes': nodes, 'edges': edges}

    def get_stats(self):
        """Return summary stats about the graph"""
        by_type = defaultdict(int)
        for _, data in self.G.nodes(data=True):
            by_type[str(data.get('type', 'unknown'))] += 1

        return {
            'total_nodes': len(self.G.nodes()),
            'total_edges': len(self.G.edges()),
            'by_type': dict(by_type)
        }