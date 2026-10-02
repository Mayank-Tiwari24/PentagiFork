import React, { useMemo } from 'react';
import { AlertCircle, ShieldAlert, CheckCircle, Database } from 'lucide-react';

interface Node {
  id: string;
  label: string;
  type: 'vector' | 'attack' | 'success';
  level: number;
}

interface Edge {
  source: string;
  target: string;
}

interface AttackGraphProps {
  nodes: Node[];
  edges: Edge[];
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ nodes, edges }) => {
  // Simple layout logic for an SVG flow
  const { nodePositions, width, height } = useMemo(() => {
    const levels: Record<number, Node[]> = {};
    let maxNodesInLevel = 0;
    
    nodes.forEach(n => {
      levels[n.level] = levels[n.level] || [];
      levels[n.level].push(n);
      maxNodesInLevel = Math.max(maxNodesInLevel, levels[n.level].length);
    });

    const levelWidth = 250;
    const nodeHeight = 100;
    
    const positions: Record<string, { x: number, y: number }> = {};
    
    Object.keys(levels).forEach(lvlStr => {
      const lvl = parseInt(lvlStr);
      const lvlNodes = levels[lvl];
      
      const startY = (maxNodesInLevel * nodeHeight - lvlNodes.length * nodeHeight) / 2;
      
      lvlNodes.forEach((node, i) => {
        positions[node.id] = {
          x: lvl * levelWidth + 50,
          y: startY + i * nodeHeight + 50
        };
      });
    });
    
    return {
      nodePositions: positions,
      width: (Object.keys(levels).length * levelWidth) + 100,
      height: maxNodesInLevel * nodeHeight + 100
    };
  }, [nodes]);

  const getIcon = (type: string) => {
    switch (type) {
      case 'vector': return <Database className="w-5 h-5 text-blue-400" />;
      case 'attack': return <ShieldAlert className="w-5 h-5 text-red-500" />;
      case 'success': return <CheckCircle className="w-5 h-5 text-green-500" />;
      default: return <AlertCircle className="w-5 h-5 text-gray-400" />;
    }
  };

  return (
    <div className="w-full h-full overflow-auto bg-slate-900 rounded-lg border border-slate-800 p-4">
      <h3 className="text-white font-semibold mb-4 text-lg">Attack Path Visualization</h3>
      <div className="relative" style={{ minWidth: width, minHeight: height }}>
        <svg className="absolute top-0 left-0 w-full h-full" style={{ zIndex: 0 }}>
          {edges.map((edge, i) => {
            const src = nodePositions[edge.source];
            const tgt = nodePositions[edge.target];
            if (!src || !tgt) return null;
            
            return (
              <line
                key={`edge-${i}`}
                x1={src.x + 100} // offset by node width approx
                y1={src.y + 30}
                x2={tgt.x}
                y2={tgt.y + 30}
                stroke="#475569"
                strokeWidth="2"
                strokeDasharray="5,5"
              />
            );
          })}
        </svg>

        {nodes.map(node => {
          const pos = nodePositions[node.id];
          if (!pos) return null;
          
          return (
            <div
              key={node.id}
              className={`absolute flex items-center gap-3 p-3 rounded-lg border bg-slate-800 shadow-lg transition-transform hover:scale-105 cursor-pointer w-48`}
              style={{
                left: pos.x,
                top: pos.y,
                zIndex: 10,
                borderColor: node.type === 'attack' ? '#ef4444' : node.type === 'success' ? '#22c55e' : '#3b82f6'
              }}
            >
              {getIcon(node.type)}
              <span className="text-slate-200 text-sm font-medium truncate">{node.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default AttackGraph;
