type CategoryCardProps = {
  title: string;
  fields: Record<string, unknown>;
};

function humanize(key: string) {
  return key.replace(/_/g, " ");
}

function formatValue(value: unknown) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : "None";
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value ?? "Unknown");
}

export function CategoryCard({ title, fields }: CategoryCardProps) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>{title}</h3>
      </div>
      <dl className="field-grid">
        {Object.entries(fields).map(([key, value]) => (
          <div key={key} className="field-row">
            <dt>{humanize(key)}</dt>
            <dd>{formatValue(value)}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
