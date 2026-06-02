#!/usr/bin/env bash
set -e

CMD=(python agent.py -d)

if [ -n "${PLUM_ISLAND}" ]; then
    CMD+=(-island "${PLUM_ISLAND}")
fi

if [ -n "${PLUM_AGENT_KEY}" ]; then
    CMD+=(-agentkey "${PLUM_AGENT_KEY}")
fi

if [ -n "${PLUM_EXT_IP}" ]; then
    CMD+=(-ipext "${PLUM_EXT_IP}")
fi

if [ "${PLUM_VERBOSE:-0}" = "1" ]; then
    CMD+=(-v)
fi

exec "${CMD[@]}"
