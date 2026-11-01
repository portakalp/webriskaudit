export type NodeStatus = "idle" | "scanning" | "complete"

export interface ScanPhase {
  label: string
  /** Ids of the graph nodes shown as active during this phase. */
  nodes: string[]
  /** How long the phase stays on screen, in milliseconds. */
  duration: number
}
