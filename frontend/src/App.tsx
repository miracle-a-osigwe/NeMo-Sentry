import { useState } from 'react'
import './App.css'

function App() {
  const [targetEndpoint, setTargetEndpoint] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [results, setResults] = useState<any>(null)

  const handleScan = async () => {
    setIsScanning(true)
    try {
      const response = await fetch('http://localhost:8000/api/v1/fuzz', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target_endpoint: targetEndpoint,
          attack_vectors: ["prompt_injection", "jailbreak"],
          num_probes: 5
        }),
      })
      const data = await response.json()
      setResults(data)
    } catch (err) {
      console.error(err)
      alert("Failed to scan. Is the backend running?")
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="App" style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1>NeMo-Sentry</h1>
      <p>Autonomous LLM Red-Teaming & Guardrail Synthesis</p>
      
      <div style={{ marginBottom: '1rem' }}>
        <input 
          type="text" 
          placeholder="Target LLM Endpoint URL" 
          value={targetEndpoint}
          onChange={(e) => setTargetEndpoint(e.target.value)}
          style={{ padding: '0.5rem', width: '300px', marginRight: '1rem' }}
        />
        <button 
          onClick={handleScan} 
          disabled={isScanning || !targetEndpoint}
          style={{ padding: '0.5rem 1rem' }}
        >
          {isScanning ? 'Fuzzing...' : 'Launch Attack Barrage'}
        </button>
      </div>

      {results && (
        <div style={{ textAlign: 'left', background: '#f5f5f5', padding: '1rem', borderRadius: '8px' }}>
          <h2>Scan Results</h2>
          <p><strong>Threat Intel Source (Tavily):</strong> {results.threat_intel_used}</p>
          
          <h3>Synthesized Guardrails (Colang)</h3>
          <pre style={{ background: '#333', color: '#fff', padding: '1rem', overflowX: 'auto' }}>
            {results.synthesized_colang}
          </pre>
          
          <h3>Probe Results</h3>
          <ul>
            {results.fuzz_results.map((r: any, idx: number) => (
              <li key={idx} style={{ color: r.success ? 'red' : 'green', marginBottom: '0.5rem' }}>
                <strong>{r.success ? 'BREACHED' : 'BLOCKED'}:</strong> {r.prompt} <br/>
                <small>{r.eval_details}</small>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

export default App
