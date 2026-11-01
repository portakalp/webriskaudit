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
  metrics: {
    dataPoints: number
    scoreAdd: number
    threatsAdd?: number
  }
}

export interface DashboardMetrics {
  testsCompleted: number
  score: number
  threats: number
  dataPoints: number
}

export interface DashboardState {
  currentPhaseIndex: number
  completedTests: string[]
  activeTests: string[]
  metrics: DashboardMetrics
  elapsedTime: number
}

export interface GraphNode {
  id: string
  name: string
  status: NodeStatus
  x: number
  y: number
}
