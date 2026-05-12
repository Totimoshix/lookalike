type JsonExportButtonProps = {
  filename: string;
  payload: unknown;
};

export function JsonExportButton({ filename, payload }: JsonExportButtonProps) {
  const handleDownload = () => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <button className="ghost-button" onClick={handleDownload} type="button">
      Export JSON
    </button>
  );
}

