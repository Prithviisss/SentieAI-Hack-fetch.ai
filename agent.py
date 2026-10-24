"""SentinelFlow: Autonomous SecOps Incident Investigation & Verified Response Agent.

Main agent entrypoint configured with Agentverse Mailbox and Agent Chat Protocol (ACP).
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
from uagents import Agent, Context

load_dotenv()

from chat_proto import chat_proto

AGENT_NAME = os.getenv("AGENT_NAME", "SentinelFlow Incident Response Agent")
AGENT_SEED = os.getenv("AGENT_SEED_PHRASE", "sentinelflow-cyber-incident-agent-seed-2026")
AGENT_PORT = int(os.getenv("AGENT_PORT", "8000"))
USE_MAILBOX = os.getenv("AGENT_MAILBOX", "True").lower() in ("true", "1", "yes")

# Initialize Agent
agent = Agent(
    name=AGENT_NAME,
    seed=AGENT_SEED,
    port=AGENT_PORT,
    mailbox=USE_MAILBOX,
)

# Attach Agent Chat Protocol (ACP) and publish manifest for ASI:One discovery
agent.include(chat_proto, publish_manifest=True)


@agent.on_event("startup")
async def startup(ctx: Context):
    ctx.logger.info("=" * 60)
    ctx.logger.info(f"🛡️  SentinelFlow Agent Initialized: {agent.name}")
    ctx.logger.info(f"📍 Agent Address: {agent.address}")
    ctx.logger.info(f"🌐 Protocol: Agent Chat Protocol (ACP) Published")
    ctx.logger.info(f"📬 Mailbox Enabled: {USE_MAILBOX}")
    ctx.logger.info("=" * 60)
    ctx.logger.info("Ready to receive cybersecurity investigation tasks via ASI:One.")


if __name__ == "__main__":
    agent.run()
