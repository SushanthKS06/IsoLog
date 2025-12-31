"""
IsoLog WebSocket Event Stream

Real-time event and alert streaming via WebSocket.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections for real-time streaming.
    """
    
    def __init__(self):
        """Initialize connection manager."""
        self._connections: Set[WebSocket] = set()
        self._subscribers: Dict[str, Set[WebSocket]] = {
            "events": set(),
            "alerts": set(),
            "all": set(),
        }
    
    async def connect(self, websocket: WebSocket, channel: str = "all"):
        """
        Accept a new WebSocket connection.
        
        Args:
            websocket: WebSocket connection
            channel: Subscription channel (events, alerts, all)
        """
        await websocket.accept()
        self._connections.add(websocket)
        
        if channel in self._subscribers:
            self._subscribers[channel].add(websocket)
        
        logger.info(f"WebSocket connected, channel: {channel}, total: {len(self._connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """
        Handle WebSocket disconnection.
        
        Args:
            websocket: WebSocket connection
        """
        self._connections.discard(websocket)
        
        for channel in self._subscribers.values():
            channel.discard(websocket)
        
        logger.debug(f"WebSocket disconnected, remaining: {len(self._connections)}")
    
    async def broadcast(self, message: Dict[str, Any], channel: str = "all"):
        """
        Broadcast message to all subscribers of a channel.
        
        Args:
            message: Message to send
            channel: Target channel
        """
        data = json.dumps(message, default=str)
        
        # Get target connections
        targets = set()
        if channel == "all":
            targets = self._connections
        else:
            targets = self._subscribers.get(channel, set()) | self._subscribers.get("all", set())
        
        # Send to all targets
        disconnected = []
        for connection in targets:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected
        for conn in disconnected:
            self.disconnect(conn)
    
    async def send_event(self, event: Dict[str, Any]):
        """
        Send an event to subscribers.
        
        Args:
            event: Event data
        """
        message = {
            "type": "event",
            "timestamp": datetime.utcnow().isoformat(),
            "data": event,
        }
        await self.broadcast(message, "events")
    
    async def send_alert(self, alert: Dict[str, Any]):
        """
        Send an alert to subscribers.
        
        Args:
            alert: Alert data
        """
        message = {
            "type": "alert",
            "timestamp": datetime.utcnow().isoformat(),
            "data": alert,
        }
        await self.broadcast(message, "alerts")
    
    async def send_stats(self, stats: Dict[str, Any]):
        """
        Send updated statistics.
        
        Args:
            stats: Statistics data
        """
        message = {
            "type": "stats",
            "timestamp": datetime.utcnow().isoformat(),
            "data": stats,
        }
        await self.broadcast(message, "all")
    
    def get_connection_count(self) -> int:
        """Get active connection count."""
        return len(self._connections)
    
    def get_channel_counts(self) -> Dict[str, int]:
        """Get subscriber count per channel."""
        return {
            channel: len(subs) 
            for channel, subs in self._subscribers.items()
        }


# Global connection manager
ws_manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, channel: str = "all"):
    """
    WebSocket endpoint handler.
    
    Args:
        websocket: WebSocket connection
        channel: Subscription channel
    """
    await ws_manager.connect(websocket, channel)
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                # Receive messages (ping/pong, commands)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle ping
                if data == "ping":
                    await websocket.send_text("pong")
                
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)
