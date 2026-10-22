/** QR desenhado em SVG a partir da matriz do servidor (linhas de "0" e "1"): nada de imagem externa nem data: URI. */
export function QrCode({ matrix, label }: { matrix: string[]; label: string }) {
  const size = matrix.length;
  const quiet = 4;
  let d = "";
  matrix.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) if (row[x] === "1") d += `M${x + quiet} ${y + quiet}h1v1h-1z`;
  });
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size + quiet * 2} ${size + quiet * 2}`} className="size-56 rounded-control bg-white" shapeRendering="crispEdges">
      <path d={d} fill="#000" />
    </svg>
  );
}
