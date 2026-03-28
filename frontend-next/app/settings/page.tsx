"use client"

import { useState } from "react"
import { Save, Plus, Trash2, TestTube } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"

interface ConnectionForm {
  name: string
  type: string
  base_url: string
  api_key: string
}

export default function SettingsPage() {
  const [connections, setConnections] = useState<ConnectionForm[]>([])
  const [apiKey, setApiKey] = useState("")
  const [model, setModel] = useState("claude-sonnet-4-20250514")
  const [automationLevel, setAutomationLevel] = useState("assisted")

  function addConnection() {
    setConnections([
      ...connections,
      { name: "", type: "splunk", base_url: "", api_key: "" },
    ])
  }

  function removeConnection(index: number) {
    setConnections(connections.filter((_, i) => i !== index))
  }

  function updateConnection(index: number, field: keyof ConnectionForm, value: string) {
    setConnections(
      connections.map((c, i) => (i === index ? { ...c, [field]: value } : c))
    )
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-text">Settings</h1>
        <p className="text-sm text-muted mt-1">
          Configure SIEM connections, API keys, and automation preferences.
        </p>
      </div>

      <Tabs defaultValue="connections">
        <TabsList>
          <TabsTrigger value="connections">SIEM Connections</TabsTrigger>
          <TabsTrigger value="api">API Keys</TabsTrigger>
          <TabsTrigger value="model">Model Routing</TabsTrigger>
          <TabsTrigger value="automation">Automation</TabsTrigger>
        </TabsList>

        {/* SIEM Connections */}
        <TabsContent value="connections" className="mt-6 space-y-4">
          {connections.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <p className="text-sm text-muted mb-4">No SIEM connections configured.</p>
                <Button onClick={addConnection}>
                  <Plus className="h-4 w-4" />
                  Add Connection
                </Button>
              </CardContent>
            </Card>
          ) : (
            <>
              {connections.map((conn, i) => (
                <Card key={i}>
                  <CardContent className="p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold">Connection {i + 1}</h3>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeConnection(i)}
                      >
                        <Trash2 className="h-4 w-4 text-red" />
                      </Button>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-xs text-muted block mb-1">Name</label>
                        <Input
                          value={conn.name}
                          onChange={(e) => updateConnection(i, "name", e.target.value)}
                          placeholder="My Splunk Instance"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted block mb-1">Type</label>
                        <select
                          value={conn.type}
                          onChange={(e) => updateConnection(i, "type", e.target.value)}
                          className="h-9 w-full rounded-lg border border-border bg-bg px-3 text-sm text-text"
                        >
                          <option value="splunk">Splunk</option>
                          <option value="sentinel">Microsoft Sentinel</option>
                          <option value="chronicle">Google Chronicle</option>
                          <option value="elastic">Elastic SIEM</option>
                          <option value="crowdstrike">CrowdStrike</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-xs text-muted block mb-1">Base URL</label>
                        <Input
                          value={conn.base_url}
                          onChange={(e) => updateConnection(i, "base_url", e.target.value)}
                          placeholder="https://splunk.example.com:8089"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted block mb-1">API Key</label>
                        <Input
                          type="password"
                          value={conn.api_key}
                          onChange={(e) => updateConnection(i, "api_key", e.target.value)}
                          placeholder="Bearer token or API key"
                        />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm">
                        <TestTube className="h-3 w-3" />
                        Test Connection
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
              <Button onClick={addConnection} variant="outline">
                <Plus className="h-4 w-4" />
                Add Another
              </Button>
            </>
          )}
        </TabsContent>

        {/* API Keys */}
        <TabsContent value="api" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Anthropic API Key</CardTitle>
              <CardDescription>
                Used for the PurpleLab AI assistant and rule generation.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3">
                <Input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="sk-ant-..."
                  className="max-w-md"
                />
                <Button>
                  <Save className="h-4 w-4" />
                  Save
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Model Routing */}
        <TabsContent value="model" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Default Model</CardTitle>
              <CardDescription>
                Choose which model handles chat and agentic tasks.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text"
              >
                <option value="claude-sonnet-4-20250514">Claude Sonnet 4</option>
                <option value="claude-opus-4-20250514">Claude Opus 4</option>
                <option value="claude-haiku-3-20250307">Claude Haiku 3.5</option>
                <option value="gpt-4o">GPT-4o (OpenAI)</option>
              </select>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Automation Level */}
        <TabsContent value="automation" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Automation Level</CardTitle>
              <CardDescription>
                Control how much the AI assistant does autonomously.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  {
                    value: "manual",
                    label: "Manual",
                    desc: "AI suggests actions, you approve each one",
                  },
                  {
                    value: "assisted",
                    label: "Assisted",
                    desc: "AI executes safe actions, asks for approval on destructive ones",
                  },
                  {
                    value: "autonomous",
                    label: "Autonomous",
                    desc: "AI executes all actions without approval (use with caution)",
                  },
                ].map((opt) => (
                  <label
                    key={opt.value}
                    className={`flex items-start gap-3 rounded-lg border p-4 cursor-pointer transition-colors ${
                      automationLevel === opt.value
                        ? "border-primary bg-primary/5"
                        : "border-border hover:border-muted"
                    }`}
                  >
                    <input
                      type="radio"
                      name="automation"
                      value={opt.value}
                      checked={automationLevel === opt.value}
                      onChange={(e) => setAutomationLevel(e.target.value)}
                      className="mt-0.5"
                    />
                    <div>
                      <div className="text-sm font-medium">{opt.label}</div>
                      <div className="text-xs text-muted mt-0.5">{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
