# knowledge_graph.py
"""
Compliance Knowledge Graph
---------------------------
Builds a directed graph connecting devices, vendors, violations,
rules, NIST controls, CIS benchmarks, severities, and config lines.

Enables full traceability: every violation can be traced back to its
exact line in the configuration file.
"""
import networkx as nx


class ComplianceKnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    # ------------------------------------------------------------
    # Node & Edge helpers
    # ------------------------------------------------------------
    def _add_node(self, node_type, node_id, **attrs):
        """Add a node with a unique ID based on type + id"""
        unique_id = str(node_type) + "::" + str(node_id)
        if unique_id not in self.graph:
            self.graph.add_node(
                unique_id,
                type=node_type,
                label=str(node_id),
                **attrs
            )
        return unique_id

    def _add_edge(self, source_id, target_id, relation, **attrs):
        """Add a directed edge with a relation label"""
        self.graph.add_edge(source_id, target_id, relation=relation, **attrs)

    # ------------------------------------------------------------
    # Build graph from an audit result
    # ------------------------------------------------------------
    def build_from_audit(self, audit):
        """Build the full knowledge graph for a single audit"""
        self.graph = nx.DiGraph()   # reset

        # ----- Device node -----
        device_node = self._add_node(
            'device',
            audit['filename'],
            vendor=audit.get('vendor', 'UNKNOWN'),
            score=audit.get('compliance_score', 0)
        )

        # ----- Vendor node -----
        vendor_node = self._add_node(
            'vendor',
            audit.get('vendor', 'UNKNOWN')
        )
        self._add_edge(device_node, vendor_node, 'belongs_to_vendor')

        # ----- Violations -----
        for i, v in enumerate(audit.get('violations', [])):
            v_node = self._add_node(
                'violation',
                'v' + str(i) + '_' + v.get('rule', 'unknown'),
                rule=v.get('rule', ''),
                description=v.get('description', ''),
                severity=v.get('severity', 'LOW'),
                line_number=v.get('line_number'),
                line_content=v.get('line_content', '')
            )
            self._add_edge(device_node, v_node, 'has_violation')

            # Rule node
            rule_node = self._add_node(
                'rule',
                v.get('rule', 'unknown'),
                description=v.get('description', '')
            )
            self._add_edge(v_node, rule_node, 'violates_rule')

            # NIST control
            if v.get('nist_control'):
                nist_node = self._add_node('nist', v['nist_control'])
                self._add_edge(v_node, nist_node, 'mapped_to_nist')

            # CIS benchmark
            if v.get('cis_benchmark'):
                cis_node = self._add_node('cis', v['cis_benchmark'])
                self._add_edge(v_node, cis_node, 'mapped_to_cis')

            # Severity
            sev_node = self._add_node('severity', v.get('severity', 'LOW'))
            self._add_edge(v_node, sev_node, 'has_severity')

            # Config line
            if v.get('line_number'):
                line_node = self._add_node(
                    'config_line',
                    'L' + str(v['line_number']),
                    content=v.get('line_content', ''),
                    line_number=v['line_number']
                )
                self._add_edge(v_node, line_node, 'at_config_line')

        # ----- Passed checks (for completeness) -----
        for i, p in enumerate(audit.get('passed_checks', [])):
            p_node = self._add_node(
                'passed_check',
                'p' + str(i) + '_' + p.get('rule', 'unknown'),
                rule=p.get('rule', ''),
                description=p.get('description', '')
            )
            self._add_edge(device_node, p_node, 'has_passed_check')

        return self.graph

    # ------------------------------------------------------------
    # Trace a violation
    # ------------------------------------------------------------
    def get_violation_trace(self, audit, rule_key):
        """Return the full trace path for a specific violation rule"""
        # Build graph if empty
        if self.graph.number_of_nodes() == 0:
            self.build_from_audit(audit)

        # Find the violation node matching the rule
        violation_id = None
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') == 'violation' and data.get('rule') == rule_key:
                violation_id = node_id
                break

        if not violation_id:
            return None

        trace = {
            'violation': dict(self.graph.nodes[violation_id]),
            'rule': None,
            'nist': None,
            'cis': None,
            'severity': None,
            'config_line': None,
            'device': None,
            'vendor': None
        }

        # Walk outgoing edges
        for _, target, edge_data in self.graph.out_edges(violation_id, data=True):
            relation = edge_data.get('relation')
            target_data = dict(self.graph.nodes[target])

            if relation == 'violates_rule':
                trace['rule'] = target_data
            elif relation == 'mapped_to_nist':
                trace['nist'] = target_data
            elif relation == 'mapped_to_cis':
                trace['cis'] = target_data
            elif relation == 'has_severity':
                trace['severity'] = target_data
            elif relation == 'at_config_line':
                trace['config_line'] = target_data

        # Walk incoming edges to find device
        for source, _, edge_data in self.graph.in_edges(violation_id, data=True):
            if edge_data.get('relation') == 'has_violation':
                device_data = dict(self.graph.nodes[source])
                trace['device'] = device_data
                # Find vendor
                for _, v_target, v_edge in self.graph.out_edges(source, data=True):
                    if v_edge.get('relation') == 'belongs_to_vendor':
                        trace['vendor'] = dict(self.graph.nodes[v_target])
                        break

        return trace

    # ------------------------------------------------------------
    # Stats & JSON export
    # ------------------------------------------------------------
    def get_stats(self):
        """Return graph statistics"""
        node_types = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get('type', 'unknown')
            node_types[t] = node_types.get(t, 0) + 1

        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'node_types': node_types
        }

    def to_json(self):
        """Export the graph as JSON for frontend visualization"""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            node = {'id': node_id}
            for k, v in data.items():
                node[k] = v
            nodes.append(node)

        edges = []
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'relation': data.get('relation', '')
            })

        return {'nodes': nodes, 'edges': edges}