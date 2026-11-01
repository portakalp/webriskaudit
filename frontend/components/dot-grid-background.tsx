export function DotGridBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div
        className="absolute inset-0 opacity-100"
        style={{
          backgroundImage: `radial-gradient(circle, #CBD5E1 1px, transparent 1px)`,
          backgroundSize: "24px 24px",
        }}
      />

      <div
        className="absolute inset-0"
        style={{
          background: `radial-gradient(ellipse 80% 70% at 50% 50%, transparent 0%, #F8FAFC 100%)`,
        }}
      />

      <div className="absolute bottom-0 right-0 w-[600px] h-[600px] bg-orange-100/50 rounded-full blur-3xl" />
      <div className="absolute top-0 left-0 w-[400px] h-[400px] bg-blue-100/40 rounded-full blur-3xl" />
    </div>
  )
}
