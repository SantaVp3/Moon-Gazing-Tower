import { useState, useEffect, useRef } from 'react';
import * as THREE from 'three';
import anime from 'animejs';
import * as d3 from 'd3-force';
import { useQuery } from '@tanstack/react-query';
import { vulnApi, Vulnerability } from '@/api/vulnerabilities';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Loader2, X, RotateCcw } from 'lucide-react';

// Types
interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  type: string;
  val: number;
  color: string;
  data: any;
  threeObject?: THREE.Object3D;
  x?: number;
  y?: number;
  z?: number;
  vx?: number;
  vy?: number;
  vz?: number;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  color?: string;
  threeObject?: THREE.Line;
}

export default function TopologyPage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isLoadingGraph, setIsLoadingGraph] = useState(true);

  // Three.js refs
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<any>(null); // We'll implement custom controls or use simple mouse events
  const animationFrameRef = useRef<number>();
  const nodesRef = useRef<GraphNode[]>([]);
  const linksRef = useRef<GraphLink[]>([]);
  const raycasterRef = useRef(new THREE.Raycaster());
  const mouseRef = useRef(new THREE.Vector2());
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(
    null
  );

  // Fetch vulnerabilities only (no more assets)
  const { data: vulnsData, isLoading: isFetchingVulns } = useQuery({
    queryKey: ['vulns', 'all'],
    queryFn: () => vulnApi.getVulnerabilities({ page: 1, pageSize: 1000 }),
  });

  const isFetching = isFetchingVulns;

  // Initialize Three.js
  useEffect(() => {
    if (!containerRef.current) return;

    // Scene setup
    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x000000, 0.0015); // Space fog
    sceneRef.current = scene;

    // Camera setup
    const camera = new THREE.PerspectiveCamera(
      60,
      containerRef.current.clientWidth / containerRef.current.clientHeight,
      0.1,
      2000
    );
    camera.position.z = 400;
    cameraRef.current = camera;

    // Renderer setup
    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(
      containerRef.current.clientWidth,
      containerRef.current.clientHeight
    );
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    containerRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // Starfield background
    const starGeometry = new THREE.BufferGeometry();
    const starMaterial = new THREE.PointsMaterial({
      color: 0xffffff,
      size: 0.5,
      transparent: true,
      opacity: 0.8,
      sizeAttenuation: true,
    });

    const starVertices = [];
    for (let i = 0; i < 2000; i++) {
      const x = (Math.random() - 0.5) * 2000;
      const y = (Math.random() - 0.5) * 2000;
      const z = (Math.random() - 0.5) * 2000;
      starVertices.push(x, y, z);
    }
    starGeometry.setAttribute(
      'position',
      new THREE.Float32BufferAttribute(starVertices, 3)
    );
    const stars = new THREE.Points(starGeometry, starMaterial);
    scene.add(stars);

    // Lights
    const ambientLight = new THREE.AmbientLight(0x404040, 2);
    scene.add(ambientLight);
    const pointLight = new THREE.PointLight(0xffffff, 2);
    pointLight.position.set(0, 0, 100);
    scene.add(pointLight);

    // Interaction handlers
    const onMouseMove = (event: MouseEvent) => {
      if (!containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      mouseRef.current.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouseRef.current.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    };

    const onClick = () => {
      if (!cameraRef.current || !sceneRef.current) return;

      raycasterRef.current.setFromCamera(mouseRef.current, cameraRef.current);

      // Find intersections with nodes
      const nodeMeshes = nodesRef.current
        .map((n) => n.threeObject)
        .filter((o): o is THREE.Object3D => o !== undefined);

      const intersects = raycasterRef.current.intersectObjects(nodeMeshes);

      if (intersects.length > 0) {
        const object = intersects[0].object;
        const node = nodesRef.current.find((n) => n.threeObject === object);
        if (node) {
          handleNodeClick(node);
        }
      } else {
        // Clicked background
        setSelectedNode(null);
      }
    };

    // Mouse drag for rotation (Simple orbit implementation)
    let isDragging = false;
    let previousMousePosition = { x: 0, y: 0 };

    const onMouseDown = (e: MouseEvent) => {
      isDragging = true;
      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging = false;
    };

    const onMouseDrag = (e: MouseEvent) => {
      if (!isDragging || !sceneRef.current) return;

      const deltaMove = {
        x: e.clientX - previousMousePosition.x,
        y: e.clientY - previousMousePosition.y,
      };

      // Rotate scene/camera group or just orbit camera
      // For simplicity, let's rotate the entire graph group if we had one,
      // or move camera. Let's move camera in a sphere.

      const radius = camera.position.length();
      const theta = Math.atan2(camera.position.x, camera.position.z);
      const phi = Math.acos(camera.position.y / radius);

      const targetTheta = theta - deltaMove.x * 0.005;
      const targetPhi = Math.max(
        0.1,
        Math.min(Math.PI - 0.1, phi - deltaMove.y * 0.005)
      );

      camera.position.x = radius * Math.sin(targetPhi) * Math.sin(targetTheta);
      camera.position.y = radius * Math.cos(targetPhi);
      camera.position.z = radius * Math.sin(targetPhi) * Math.cos(targetTheta);

      camera.lookAt(0, 0, 0);

      previousMousePosition = { x: e.clientX, y: e.clientY };
    };

    // Zoom handler
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const zoomSpeed = 0.1;
      const direction = e.deltaY > 0 ? 1 : -1;
      const factor = 1 + direction * zoomSpeed;

      // Limit zoom
      if (
        camera.position.length() * factor > 10 &&
        camera.position.length() * factor < 1000
      ) {
        camera.position.multiplyScalar(factor);
      }
    };

    containerRef.current.addEventListener('mousemove', onMouseMove);
    containerRef.current.addEventListener('click', onClick);
    containerRef.current.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mouseup', onMouseUp);
    window.addEventListener('mousemove', onMouseDrag);
    containerRef.current.addEventListener('wheel', onWheel, { passive: false });

    // Animation Loop
    const animate = () => {
      animationFrameRef.current = requestAnimationFrame(animate);

      // Rotate stars slowly
      stars.rotation.y += 0.0002;

      // Auto-rotate camera if not dragging
      if (!isDragging && cameraRef.current) {
        const camera = cameraRef.current;
        const x = camera.position.x;
        const z = camera.position.z;
        const speed = 0.001; // Rotation speed

        camera.position.x = x * Math.cos(speed) - z * Math.sin(speed);
        camera.position.z = x * Math.sin(speed) + z * Math.cos(speed);
        camera.lookAt(0, 0, 0);
      }

      // Update raycaster for hover effects
      if (cameraRef.current && sceneRef.current) {
        raycasterRef.current.setFromCamera(mouseRef.current, cameraRef.current);
        const nodeMeshes = nodesRef.current
          .map((n) => n.threeObject)
          .filter((o): o is THREE.Object3D => o !== undefined);

        const intersects = raycasterRef.current.intersectObjects(nodeMeshes);

        // Reset all scales
        nodesRef.current.forEach((node) => {
          if (node.threeObject && node !== selectedNode) {
            // Smooth scale back to original
            node.threeObject.scale.lerp(new THREE.Vector3(1, 1, 1), 0.1);
          }
        });

        if (intersects.length > 0) {
          const object = intersects[0].object;
          // Scale up hovered
          object.scale.lerp(new THREE.Vector3(1.5, 1.5, 1.5), 0.1);
          document.body.style.cursor = 'pointer';
        } else {
          document.body.style.cursor = 'default';
        }
      }

      if (rendererRef.current && sceneRef.current && cameraRef.current) {
        rendererRef.current.render(sceneRef.current, cameraRef.current);
      }
    };
    animate();

    // Cleanup
    return () => {
      if (animationFrameRef.current)
        cancelAnimationFrame(animationFrameRef.current);
      if (rendererRef.current) rendererRef.current.dispose();
      if (containerRef.current) {
        containerRef.current.removeEventListener('mousemove', onMouseMove);
        containerRef.current.removeEventListener('click', onClick);
        containerRef.current.removeEventListener('mousedown', onMouseDown);
        containerRef.current.removeEventListener('wheel', onWheel);
        // Remove children
        while (containerRef.current.firstChild) {
          containerRef.current.removeChild(containerRef.current.firstChild);
        }
      }
      window.removeEventListener('mouseup', onMouseUp);
      window.removeEventListener('mousemove', onMouseDrag);
      if (simulationRef.current) simulationRef.current.stop();
    };
  }, []);

  // Data processing and Graph generation - Now based on vulnerabilities
  useEffect(() => {
    const realVulns = vulnsData?.data?.list || [];

    // Group vulnerabilities by target/URL
    const targetMap = new Map<string, Vulnerability[]>();
    realVulns.forEach((v: Vulnerability) => {
      const target = v.target || v.url || 'unknown';
      const list = targetMap.get(target) || [];
      list.push(v);
      targetMap.set(target, list);
    });

    // Structure data into the "Galaxy" format
    const dataList: any[] = [];

    // 1. Create Virtual Core (Central Hub)
    const coreId = 'vuln-core-01';
    const totalTargets = targetMap.size;
    const totalVulns = realVulns.length;
    const criticalCount = realVulns.filter(
      (v: Vulnerability) => v.severity === 'critical'
    ).length;
    const highCount = realVulns.filter(
      (v: Vulnerability) => v.severity === 'high'
    ).length;

    dataList.push({
      id: coreId,
      target: '漏洞中心',
      type: 'core',
      status: 'active',
      tags: ['HQ'],
      val: 20,
      color: '#22d3ee',
      latency: '1ms',
      region: '数据中心',
      owner: 'Security Team',
      load: Math.min(100, Math.floor(totalTargets / 10)),
      ip: 'N/A',
      description: `漏洞数据中心。目标总数: ${totalTargets}，漏洞总数: ${totalVulns}${criticalCount > 0 ? `，严重: ${criticalCount}` : ''}${highCount > 0 ? `，高危: ${highCount}` : ''}`,
    });

    // 2. Create Virtual Clusters based on Severity
    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const severityMap: Record<string, string> = {
      critical: '严重漏洞',
      high: '高危漏洞',
      medium: '中危漏洞',
      low: '低危漏洞',
      info: '信息提示',
    };
    const severityColors: Record<string, string> = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6',
      info: '#64748b',
    };

    severities.forEach((s) => {
      const sevVulns = realVulns.filter((v: Vulnerability) => v.severity === s);
      if (sevVulns.length === 0) return; // Skip empty clusters

      const clusterId = `cluster-${s}`;

      dataList.push({
        id: clusterId,
        target: severityMap[s] || s.toUpperCase(),
        type: 'cluster',
        status: 'active',
        tags: ['Severity'],
        val: 12,
        color: severityColors[s] || '#c084fc',
        parentId: coreId,
        latency: '-',
        region: '-',
        owner: 'Auto',
        load: Math.floor((sevVulns.length / totalVulns) * 100),
        ip: 'N/A',
        description: `${severityMap[s]} 类型集合。包含 ${sevVulns.length} 个漏洞。`,
      });
    });

    // 3. Map Vulnerabilities to Clusters
    realVulns.forEach((vuln: Vulnerability) => {
      const nodeVuln = { ...vuln } as any;

      // Assign visual properties
      nodeVuln.type = 'leaf';
      nodeVuln.originalSeverity = vuln.severity;
      nodeVuln.val = 4;
      nodeVuln.color = severityColors[vuln.severity] || '#64748b';
      nodeVuln.parentId = `cluster-${vuln.severity}`;

      // Map metadata
      nodeVuln.latency = '-';
      nodeVuln.region = vuln.target || '未知';
      nodeVuln.owner = 'Security Team';
      nodeVuln.load = 0;
      nodeVuln.ip = vuln.target || vuln.url || 'N/A';
      nodeVuln.description =
        vuln.name || (vuln as any).templateId || `${vuln.severity} 漏洞`;

      // Size based on severity
      if (vuln.severity === 'critical') {
        nodeVuln.val = 6;
      } else if (vuln.severity === 'high') {
        nodeVuln.val = 5;
      }

      dataList.push(nodeVuln);
    });

    if (dataList.length === 0 || !sceneRef.current) {
      setIsLoadingGraph(false);
      return;
    }

    // Clear existing graph
    nodesRef.current.forEach((n) => {
      if (n.threeObject) sceneRef.current?.remove(n.threeObject);
    });
    linksRef.current.forEach((l) => {
      if (l.threeObject) sceneRef.current?.remove(l.threeObject);
    });

    // Process Data
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const nodeMap = new Map<string, GraphNode>();

    const addNode = (id: string, name: string, type: string, data?: any) => {
      if (!nodeMap.has(id)) {
        // Use data provided color/val or defaults
        let color = data?.color || '#ffffff';
        let val = data?.val || 5;

        if (!data?.color) {
          switch (type) {
            case 'domain':
              color = '#a78bfa';
              val = 8;
              break;
            case 'ip':
              color = '#60a5fa';
              val = 6;
              break;
            case 'web':
              color = '#34d399';
              val = 6;
              break;
            case 'app':
              color = '#f472b6';
              val = 6;
              break;
            default:
              color = '#9ca3af';
          }
        }

        const node: GraphNode = {
          id,
          name,
          type,
          val,
          color,
          data: data || { name, type },
          x: (Math.random() - 0.5) * 100,
          y: (Math.random() - 0.5) * 100,
          z: (Math.random() - 0.5) * 50,
        };
        nodes.push(node);
        nodeMap.set(id, node);
      }
      return nodeMap.get(id)!;
    };

    dataList.forEach((item: any) => {
      addNode(item.id, item.target, item.type, item);

      // Handle explicit parent-child relationships (Mock Data & Real Data Structure)
      if (item.parentId) {
        links.push({
          source: item.parentId,
          target: item.id,
          color: 'rgba(255, 255, 255, 0.15)',
        });
      }

      // Handle legacy domain/ip relationships (Only if we want extra links, but tree structure is cleaner)
      // We skip this for now to maintain the clean "Star Map" look
    });

    nodesRef.current = nodes;
    linksRef.current = links;

    // Create 3D Objects
    // 1. Glow Sprite Texture (Sharp Center)
    const canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    const context = canvas.getContext('2d');
    if (context) {
      const gradient = context.createRadialGradient(64, 64, 0, 64, 64, 64);
      gradient.addColorStop(0, 'rgba(255,255,255,1)');
      gradient.addColorStop(0.2, 'rgba(255,255,255,0.8)');
      gradient.addColorStop(0.5, 'rgba(255,255,255,0.2)');
      gradient.addColorStop(1, 'rgba(0,0,0,0)');
      context.fillStyle = gradient;
      context.fillRect(0, 0, 128, 128);
    }
    const glowTexture = new THREE.CanvasTexture(canvas);

    // 2. Outer Glow Texture (Soft Halo)
    const canvas2 = document.createElement('canvas');
    canvas2.width = 128;
    canvas2.height = 128;
    const context2 = canvas2.getContext('2d');
    if (context2) {
      const gradient = context2.createRadialGradient(64, 64, 0, 64, 64, 64);
      gradient.addColorStop(0, 'rgba(255,255,255,0.5)');
      gradient.addColorStop(0.4, 'rgba(255,255,255,0.2)');
      gradient.addColorStop(1, 'rgba(0,0,0,0)');
      context2.fillStyle = gradient;
      context2.fillRect(0, 0, 128, 128);
    }
    const outerGlowTexture = new THREE.CanvasTexture(canvas2);

    // 3. Text Label Texture Helper
    const createTextSprite = (text: string, color: string) => {
      const fontface = 'Arial';
      const fontsize = 24;
      const borderThickness = 4;
      const padding = 12;

      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      if (!context) return null;

      context.font = `bold ${fontsize}px ${fontface}`;
      const metrics = context.measureText(text);
      const textWidth = metrics.width;

      canvas.width = textWidth + padding * 2 + borderThickness * 2;
      canvas.height = fontsize * 1.4 + padding + borderThickness * 2;

      // Background (Rounded Rect)
      context.fillStyle = 'rgba(15, 23, 42, 0.8)'; // Slate-900 with opacity
      context.strokeStyle = color;
      context.lineWidth = borderThickness;

      // Round Rect function
      const x = borderThickness;
      const y = borderThickness;
      const w = canvas.width - borderThickness * 2;
      const h = canvas.height - borderThickness * 2;
      const r = 10;

      context.beginPath();
      context.moveTo(x + r, y);
      context.lineTo(x + w - r, y);
      context.quadraticCurveTo(x + w, y, x + w, y + r);
      context.lineTo(x + w, y + h - r);
      context.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
      context.lineTo(x + r, y + h);
      context.quadraticCurveTo(x, y + h, x, y + h - r);
      context.lineTo(x, y + r);
      context.quadraticCurveTo(x, y, x + r, y);
      context.closePath();
      context.fill();
      // context.stroke() // Optional border

      // Text
      context.font = `bold ${fontsize}px ${fontface}`;
      context.fillStyle = 'rgba(255, 255, 255, 1)';
      context.textAlign = 'center';
      context.textBaseline = 'middle';
      context.fillText(text, canvas.width / 2, canvas.height / 2);

      const texture = new THREE.CanvasTexture(canvas);
      const spriteMaterial = new THREE.SpriteMaterial({
        map: texture,
        transparent: true,
        depthTest: false,
      });
      const sprite = new THREE.Sprite(spriteMaterial);
      sprite.scale.set(canvas.width / 10, canvas.height / 10, 1);
      return sprite;
    };

    nodes.forEach((node) => {
      const group = new THREE.Group();

      // Inner Core Sprite
      const material = new THREE.SpriteMaterial({
        map: glowTexture,
        color: new THREE.Color(node.color),
        transparent: true,
        blending: THREE.AdditiveBlending,
      });
      const sprite = new THREE.Sprite(material);
      sprite.scale.set(node.val * 1.5, node.val * 1.5, 1);
      group.add(sprite);

      // Outer Halo for Core/Cluster
      if (node.type === 'core' || node.type === 'cluster') {
        const haloMaterial = new THREE.SpriteMaterial({
          map: outerGlowTexture,
          color: new THREE.Color(node.color),
          transparent: true,
          blending: THREE.AdditiveBlending,
          opacity: 0.4,
        });
        const halo = new THREE.Sprite(haloMaterial);
        halo.scale.set(node.val * 5, node.val * 5, 1);
        group.add(halo);
      }

      if (
        node.x !== undefined &&
        node.y !== undefined &&
        node.z !== undefined
      ) {
        group.position.set(node.x, node.y, node.z);
      }

      // Add Label for Core and Cluster nodes
      if (node.type === 'core' || node.type === 'cluster') {
        const labelSprite = createTextSprite(node.name, node.color);
        if (labelSprite) {
          labelSprite.position.set(0, node.val + 4, 0); // Offset above node
          group.add(labelSprite);
        }
      }

      sceneRef.current?.add(group);
      node.threeObject = group;
    });

    links.forEach((link) => {
      const material = new THREE.LineBasicMaterial({
        color: 0x555555,
        transparent: true,
        opacity: 0.15, // Very subtle lines
      });
      const geometry = new THREE.BufferGeometry();
      const line = new THREE.Line(geometry, material);
      sceneRef.current?.add(line);
      link.threeObject = line;
    });

    // D3 Force Simulation
    simulationRef.current = d3
      .forceSimulation<GraphNode, GraphLink>(nodes)
      .force(
        'link',
        d3
          .forceLink<GraphNode, GraphLink>(links)
          .id((d: any) => d.id)
          .distance(50)
      )
      .force('charge', d3.forceManyBody().strength(-100))
      .force('center', d3.forceCenter(0, 0))
      .on('tick', () => {
        // Update positions
        nodes.forEach((node) => {
          if (node.threeObject) {
            // Keep z relatively stable or animate it slightly
            node.threeObject.position.set(
              node.x || 0,
              node.y || 0,
              node.z || 0
            );
          }
        });

        links.forEach((link) => {
          if (link.threeObject) {
            const source = link.source as GraphNode;
            const target = link.target as GraphNode;
            const positions = new Float32Array([
              source.x || 0,
              source.y || 0,
              source.z || 0,
              target.x || 0,
              target.y || 0,
              target.z || 0,
            ]);
            link.threeObject.geometry.setAttribute(
              'position',
              new THREE.BufferAttribute(positions, 3)
            );
            link.threeObject.geometry.attributes.position.needsUpdate = true;
          }
        });
      })
      .on('end', () => {
        setIsLoadingGraph(false);
      });

    // Safety timeout to ensure loading state is cleared
    const timer = setTimeout(() => setIsLoadingGraph(false), 2000);
    return () => clearTimeout(timer);
  }, [vulnsData]);

  // Camera Animation Helper
  const flyToNode = (node: GraphNode) => {
    if (!cameraRef.current || (!controlsRef.current && !node.x)) return;

    const targetPos = {
      x: node.x || 0,
      y: node.y || 0,
      z: (node.z || 0) + 50, // Offset
    };

    const currentPos = cameraRef.current.position;

    anime({
      targets: currentPos,
      x: targetPos.x,
      y: targetPos.y,
      z: targetPos.z,
      duration: 2000,
      easing: 'easeInOutCubic',
      update: () => {
        cameraRef.current?.lookAt(node.x || 0, node.y || 0, node.z || 0);
      },
    });
  };

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
    flyToNode(node);
  };

  const resetCamera = () => {
    if (!cameraRef.current) return;
    anime({
      targets: cameraRef.current.position,
      x: 0,
      y: 0,
      z: 400,
      duration: 1500,
      easing: 'easeInOutQuad',
      update: () => {
        cameraRef.current?.lookAt(0, 0, 0);
      },
    });
    setSelectedNode(null);
  };

  return (
    <div className="h-[calc(100vh-8rem)] w-full relative bg-black overflow-hidden rounded-lg border border-slate-800 shadow-2xl">
      {/* 3D Container */}
      <div ref={containerRef} className="w-full h-full cursor-move" />

      {/* Loading Overlay */}
      {(isFetching || isLoadingGraph) && (
        <div className="absolute inset-0 flex flex-col items-center justify-center z-50 bg-black/80 backdrop-blur-sm">
          <Loader2 className="h-10 w-10 animate-spin text-primary mb-4" />
          <p className="text-slate-400 animate-pulse">
            Initializing Galaxy Simulation...
          </p>
        </div>
      )}

      {/* Controls */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-2 z-10">
        <Button
          variant="secondary"
          size="icon"
          onClick={resetCamera}
          title="Reset View"
        >
          <RotateCcw className="h-4 w-4" />
        </Button>
      </div>

      {/* Detail Panel */}
      {selectedNode && (
        <div className="absolute top-4 right-4 w-96 animate-in slide-in-from-right-10 fade-in duration-300 z-20">
          <Card className="bg-slate-950/90 border-slate-800 backdrop-blur-md text-slate-100 shadow-2xl overflow-hidden">
            {/* Header */}
            <div className="relative p-6 pb-4 border-b border-slate-800/50">
              <div className="absolute top-0 left-0 w-1 h-full bg-cyan-500/50"></div>
              <div className="flex justify-between items-start mb-1">
                <span className="text-[10px] font-bold tracking-widest text-cyan-400 uppercase">
                  Asset Details
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6 -mt-1 -mr-2 text-slate-500 hover:text-white hover:bg-white/10"
                  onClick={() => setSelectedNode(null)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <h2 className="text-2xl font-bold text-white mb-1">
                {selectedNode.name}
              </h2>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-500">ID:</span>
                <span className="text-xs font-mono text-cyan-400">
                  {selectedNode.id.toUpperCase()}
                </span>
              </div>
            </div>

            <CardContent className="p-6 space-y-6">
              {/* Status Cards */}
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-800">
                  <div className="text-xs text-slate-500 mb-1">运行状态</div>
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-2 h-2 rounded-full ${selectedNode.data.status === 'active' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500'}`}
                    ></div>
                    <span
                      className={`font-medium ${selectedNode.data.status === 'active' ? 'text-green-400' : 'text-red-400'}`}
                    >
                      {selectedNode.data.status === 'active' ? '正常' : '异常'}
                    </span>
                  </div>
                </div>
                <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-800">
                  <div className="text-xs text-slate-500 mb-1">网络延迟</div>
                  <div className="font-mono font-medium text-cyan-400">
                    {selectedNode.data.latency || '12ms'}
                  </div>
                </div>
              </div>

              {/* Metadata List */}
              <div className="space-y-3 text-sm">
                <div className="flex justify-between items-center py-1 border-b border-slate-800/50">
                  <span className="text-slate-500">IP 地址</span>
                  <span className="font-mono text-slate-300">
                    {selectedNode.data.ip || '10.5.0.1'}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/50">
                  <span className="text-slate-500">区域</span>
                  <span className="text-slate-300">
                    {selectedNode.data.region || '未知区域'}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/50">
                  <span className="text-slate-500">负责人</span>
                  <span className="text-slate-300">
                    {selectedNode.data.owner || 'Admin'}
                  </span>
                </div>
                <div className="flex justify-between items-center py-1 border-b border-slate-800/50">
                  <span className="text-slate-500">负载</span>
                  <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 rounded-full"
                      style={{ width: `${selectedNode.data.load || 45}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Description Box */}
              <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-lg p-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedNode.data.description ||
                    '节点数据加载完毕。该节点作为核心路由交换节点，承载主要数据流量。'}
                </p>
              </div>

              {/* Vulnerability Stats (If any) */}
              {selectedNode.data.vulns &&
                selectedNode.data.vulns.length > 0 && (
                  <div className="bg-red-950/20 border border-red-900/30 rounded-lg p-3">
                    <div className="text-xs text-red-400 mb-2 font-bold uppercase tracking-wider">
                      Security Risks
                    </div>
                    <div className="flex gap-2">
                      {selectedNode.data.vulns.filter(
                        (v: any) => v.severity === 'critical'
                      ).length > 0 && (
                        <Badge className="bg-red-600 hover:bg-red-700 text-white border-0">
                          CRITICAL:{' '}
                          {
                            selectedNode.data.vulns.filter(
                              (v: any) => v.severity === 'critical'
                            ).length
                          }
                        </Badge>
                      )}
                      {selectedNode.data.vulns.filter(
                        (v: any) => v.severity === 'high'
                      ).length > 0 && (
                        <Badge className="bg-orange-600 hover:bg-orange-700 text-white border-0">
                          HIGH:{' '}
                          {
                            selectedNode.data.vulns.filter(
                              (v: any) => v.severity === 'high'
                            ).length
                          }
                        </Badge>
                      )}
                      {selectedNode.data.vulns.filter(
                        (v: any) => v.severity === 'medium'
                      ).length > 0 && (
                        <Badge className="bg-yellow-600 hover:bg-yellow-700 text-white border-0">
                          MED:{' '}
                          {
                            selectedNode.data.vulns.filter(
                              (v: any) => v.severity === 'medium'
                            ).length
                          }
                        </Badge>
                      )}
                    </div>
                  </div>
                )}

              {/* Action Button */}
              <Button className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-6 shadow-[0_0_20px_rgba(8,145,178,0.3)] transition-all duration-300">
                查看监控大屏
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Header Badge */}
      <div className="absolute top-6 left-6 z-10">
        <div className="flex items-center gap-2 px-4 py-2 bg-slate-900/80 backdrop-blur-md border border-slate-700 rounded-full shadow-lg">
          <div className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)] animate-pulse" />
          <span className="text-sm font-bold tracking-wider text-slate-100">
            资产星图
          </span>
        </div>
      </div>

      {/* Instructions */}
      <div className="absolute bottom-6 left-6 z-10 text-xs text-slate-500 space-y-1 font-mono pointer-events-none select-none">
        <p>[左键拖拽] 旋转视图 ■</p>
        <p>[滚轮] 缩放视图</p>
        <p>[点击节点] 查看详情</p>
      </div>
    </div>
  );
}
