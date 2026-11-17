function show(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : String(Number(value.toPrecision(6)));
  if (Array.isArray(value) && value.every((item) => item === null || typeof item !== "object")) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** A plain table for query results. Cells are text; numbers are right-aligned. */
export function DataTable({
  columns,
  rows,
  highlight,
  caption,
}: {
  columns: string[];
  rows: unknown[][];
  highlight?: (row: unknown[]) => boolean;
  caption?: string;
}) {
  if (!rows.length) return <p className="muted">No rows.</p>;
  return (
    <div className="table-scroll" tabIndex={0} role="region" aria-label={caption ?? "Result table"}>
      <table className="data">
        <thead>
          <tr>
            {columns.map((name) => (
              <th key={name} scope="col">
                {name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className={highlight?.(row) ? "is-highlighted" : undefined}>
              {row.map((value, column) => (
                <td key={column} className={typeof value === "number" ? "num" : undefined}>
                  {show(value)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Rows given as objects, e.g. the overview's "top sources". */
export function ObjectTable({ rows, caption }: { rows: Record<string, unknown>[]; caption?: string }) {
  if (!rows.length) return <p className="muted">No rows.</p>;
  const columns = Object.keys(rows[0]);
  return <DataTable columns={columns} rows={rows.map((row) => columns.map((c) => row[c]))} caption={caption} />;
}
