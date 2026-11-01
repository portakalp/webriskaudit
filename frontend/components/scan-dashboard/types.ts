export type NodeStatus = "idle" | "scanning" | "complete" | "failed"

export interface SecurityTest {
  id: string
  name: string
  icon: string
}

export interface ScanPhase {
  name: string
  tests: string[]
  duration: number
}

export interface DashboardState {
  currentPhaseIndex: number
  completedTests: string[]
  activeTests: string[]
}

export interface GraphNode {
  id: string
  name: string
  status: NodeStatus
  x: number
  y: number
}
