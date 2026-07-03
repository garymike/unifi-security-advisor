export function compareVersions(a: string, b: string): number {
  const segsA = a.split('.').map(s => parseInt(s, 10));
  const segsB = b.split('.').map(s => parseInt(s, 10));
  const len = Math.max(segsA.length, segsB.length);
  for (let i = 0; i < len; i++) {
    const numA = Number.isNaN(segsA[i]) || segsA[i] === undefined ? 0 : segsA[i]!;
    const numB = Number.isNaN(segsB[i]) || segsB[i] === undefined ? 0 : segsB[i]!;
    if (numA !== numB) return numA - numB;
  }
  return 0;
}
