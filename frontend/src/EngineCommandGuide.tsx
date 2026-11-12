const commands = {
  nucleiInstall: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10",
  nucleiUpdate: "nuclei -update-templates",
  nucleiScan: "nuclei -u https://staging.example.com -severity info,low,medium,high,critical -rl 5 -timeout 10 -retries 1 -jsonl -o nuclei-results.jsonl",
  shannonRun: "npx @keygraph/shannon@3.5.0 start -u https://staging.example.com -r https://github.com/your-org/your-app",
};

function CommandBlock({ title, command, note }: { title: string; command: string; note?: string }) {
  return <div className="engine-command">
    <div className="engine-command-heading"><strong>{title}</strong><button className="text-button" type="button" onClick={() => void navigator.clipboard?.writeText(command)}>Copy command</button></div>
    <pre><code>{command}</code></pre>
    {note && <small>{note}</small>}
  </div>;
}

export function EngineCommandGuide() {
  return <section className="engine-command-guide">
    <div className="panel-heading">
      <div><p className="eyebrow">OPERATOR QUICK REFERENCE</p><h3>Nuclei &amp; Shannon CLI commands</h3></div>
      <span className="tag">Manual / isolated runner setup</span>
    </div>
    <p className="integration-note">
      These commands install and run the standalone tools on an authorized assessment workstation or isolated runner.
      They do not install either engine inside the OpsAegis API container or enable the OpsAegis dispatch adapters.
    </p>
    <div className="engine-command-columns">
      <article className="engine-command-card">
        <div><p className="eyebrow">VULNERABILITY SCANNING</p><h4>Nuclei v3.4.10</h4></div>
        <CommandBlock title="Install (Go required)" command={commands.nucleiInstall} note="Install Go first. Ensure the Go bin directory is on PATH." />
        <CommandBlock title="Update templates" command={commands.nucleiUpdate} />
        <CommandBlock title="Run a bounded assessment" command={commands.nucleiScan} note="Replace the example with an HTTPS staging target you own or have written permission to test. The command limits request rate and stores JSONL output." />
      </article>
      <article className="engine-command-card">
        <div><p className="eyebrow">AI-DRIVEN APPLICATION TESTING</p><h4>Shannon v3.5.0</h4></div>
        <CommandBlock title="Prerequisites" command="node --version  # Node.js 22+\ndocker --version # Docker Engine must be running" note="Shannon launches disposable Docker workers. Use a dedicated, isolated host." />
        <CommandBlock title="Start an authorized assessment" command={commands.shannonRun} note="Replace both examples with your approved staging URL and matching source repository. Do not point Shannon at production or third-party systems." />
        <p className="integration-note">Shannon can perform real exploitation. Keep it on a dedicated disposable runner with strict outbound allowlists, a written authorization record and model-provider budget limits.</p>
      </article>
    </div>
    <p className="integration-note">
      OpsAegis dispatch remains disabled until its dedicated Nuclei worker and isolated Shannon bridge are deployed, health-checked and configured with enforced egress restrictions. A local CLI run is not automatically imported into OpsAegis.
    </p>
  </section>;
}
