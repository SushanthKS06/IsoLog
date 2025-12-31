"""
IsoLog Behavioral Baseline

Build and maintain normal behavior profiles for anomaly detection.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class UserProfile:
    """User behavior profile."""
    username: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    login_hours: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    login_days: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    source_ips: Set[str] = field(default_factory=set)
    actions: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    hosts: Set[str] = field(default_factory=set)
    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0


@dataclass
class HostProfile:
    """Host behavior profile."""
    hostname: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    active_hours: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    users: Set[str] = field(default_factory=set)
    processes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    source_ips: Set[str] = field(default_factory=set)
    dest_ports: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    total_events: int = 0


class BehavioralBaseline:
    """
    Build and maintain behavioral baselines for users and hosts.
    
    Used to detect deviations from normal behavior patterns.
    """
    
    def __init__(
        self,
        baseline_path: str = "./data/baselines",
        learning_days: int = 7,
        min_events: int = 100,
    ):
        """
        Initialize behavioral baseline.
        
        Args:
            baseline_path: Directory for baseline data
            learning_days: Days of data for initial learning
            min_events: Minimum events before baseline is active
        """
        self.baseline_path = Path(baseline_path)
        self.baseline_path.mkdir(parents=True, exist_ok=True)
        
        self.learning_days = learning_days
        self.min_events = min_events
        
        self._user_profiles: Dict[str, UserProfile] = {}
        self._host_profiles: Dict[str, HostProfile] = {}
        self._learning_mode = True
        self._events_processed = 0
        self._start_time = datetime.utcnow()
        
        # Load existing baselines
        self._load_baselines()
    
    def update(self, event: Dict[str, Any]):
        """
        Update baselines with new event.
        
        Args:
            event: Event data
        """
        self._events_processed += 1
        
        # Extract event info
        timestamp = self._parse_timestamp(event)
        user = event.get("user", {}).get("name", "")
        host = event.get("host", {}).get("name", "")
        source_ip = event.get("source", {}).get("ip", "")
        action = event.get("event", {}).get("action", "")
        outcome = event.get("event", {}).get("outcome", "")
        process = event.get("process", {}).get("name", "")
        dest_port = event.get("destination", {}).get("port", 0)
        
        # Update user profile
        if user:
            self._update_user_profile(
                user, timestamp, source_ip, action, outcome, host
            )
        
        # Update host profile
        if host:
            self._update_host_profile(
                host, timestamp, user, process, source_ip, dest_port
            )
        
        # Check if learning complete
        if self._learning_mode:
            elapsed = datetime.utcnow() - self._start_time
            if (elapsed.days >= self.learning_days and 
                self._events_processed >= self.min_events):
                self._learning_mode = False
                self._save_baselines()
                logger.info("Behavioral baseline learning complete")
    
    def _update_user_profile(
        self,
        username: str,
        timestamp: datetime,
        source_ip: str,
        action: str,
        outcome: str,
        host: str,
    ):
        """Update user behavior profile."""
        if username not in self._user_profiles:
            self._user_profiles[username] = UserProfile(username=username)
        
        profile = self._user_profiles[username]
        profile.last_seen = timestamp
        profile.total_events += 1
        
        if timestamp:
            profile.login_hours[timestamp.hour] += 1
            profile.login_days[timestamp.weekday()] += 1
        
        if source_ip:
            profile.source_ips.add(source_ip)
        
        if action:
            profile.actions[action] += 1
        
        if host:
            profile.hosts.add(host)
        
        if outcome == "failure":
            profile.failed_logins += 1
        elif outcome == "success" and "login" in action.lower():
            profile.successful_logins += 1
    
    def _update_host_profile(
        self,
        hostname: str,
        timestamp: datetime,
        user: str,
        process: str,
        source_ip: str,
        dest_port: int,
    ):
        """Update host behavior profile."""
        if hostname not in self._host_profiles:
            self._host_profiles[hostname] = HostProfile(hostname=hostname)
        
        profile = self._host_profiles[hostname]
        profile.last_seen = timestamp
        profile.total_events += 1
        
        if timestamp:
            profile.active_hours[timestamp.hour] += 1
        
        if user:
            profile.users.add(user)
        
        if process:
            profile.processes[process] += 1
        
        if source_ip:
            profile.source_ips.add(source_ip)
        
        if dest_port:
            profile.dest_ports[dest_port] += 1
    
    def check_user_anomaly(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if event is anomalous for user.
        
        Returns:
            Anomaly indicators
        """
        if self._learning_mode:
            return {"learning": True}
        
        user = event.get("user", {}).get("name", "")
        if not user or user not in self._user_profiles:
            return {"unknown_user": True}
        
        profile = self._user_profiles[user]
        anomalies = {}
        
        # Check timestamp
        timestamp = self._parse_timestamp(event)
        if timestamp:
            hour = timestamp.hour
            day = timestamp.weekday()
            
            # Unusual hour
            hour_total = sum(profile.login_hours.values())
            if hour_total > 0:
                hour_pct = profile.login_hours.get(hour, 0) / hour_total
                if hour_pct < 0.01:  # Less than 1% of activity
                    anomalies["unusual_hour"] = hour
            
            # Unusual day
            day_total = sum(profile.login_days.values())
            if day_total > 0:
                day_pct = profile.login_days.get(day, 0) / day_total
                if day_pct < 0.01:
                    anomalies["unusual_day"] = day
        
        # New source IP
        source_ip = event.get("source", {}).get("ip", "")
        if source_ip and source_ip not in profile.source_ips:
            anomalies["new_source_ip"] = source_ip
        
        # New host
        host = event.get("host", {}).get("name", "")
        if host and host not in profile.hosts:
            anomalies["new_host"] = host
        
        # Unusual action
        action = event.get("event", {}).get("action", "")
        if action and action not in profile.actions:
            anomalies["new_action"] = action
        
        return anomalies
    
    def check_host_anomaly(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if event is anomalous for host.
        
        Returns:
            Anomaly indicators
        """
        if self._learning_mode:
            return {"learning": True}
        
        host = event.get("host", {}).get("name", "")
        if not host or host not in self._host_profiles:
            return {"unknown_host": True}
        
        profile = self._host_profiles[host]
        anomalies = {}
        
        # New user
        user = event.get("user", {}).get("name", "")
        if user and user not in profile.users:
            anomalies["new_user"] = user
        
        # New process
        process = event.get("process", {}).get("name", "")
        if process and process not in profile.processes:
            anomalies["new_process"] = process
        
        # New destination port
        dest_port = event.get("destination", {}).get("port", 0)
        if dest_port and dest_port not in profile.dest_ports:
            anomalies["new_dest_port"] = dest_port
        
        return anomalies
    
    def get_anomaly_score(self, event: Dict[str, Any]) -> float:
        """
        Calculate overall anomaly score based on baseline.
        
        Returns:
            Score from 0 (normal) to 1 (anomalous)
        """
        user_anomalies = self.check_user_anomaly(event)
        host_anomalies = self.check_host_anomaly(event)
        
        # Count anomaly indicators
        score = 0.0
        
        if user_anomalies.get("unusual_hour"):
            score += 0.2
        if user_anomalies.get("unusual_day"):
            score += 0.15
        if user_anomalies.get("new_source_ip"):
            score += 0.25
        if user_anomalies.get("new_host"):
            score += 0.15
        if user_anomalies.get("new_action"):
            score += 0.1
        
        if host_anomalies.get("new_user"):
            score += 0.2
        if host_anomalies.get("new_process"):
            score += 0.15
        if host_anomalies.get("new_dest_port"):
            score += 0.1
        
        return min(score, 1.0)
    
    def _parse_timestamp(self, event: Dict[str, Any]) -> Optional[datetime]:
        """Parse event timestamp."""
        ts = event.get("timestamp") or event.get("@timestamp")
        
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                pass
        return None
    
    def _save_baselines(self):
        """Save baselines to disk."""
        try:
            # Save user profiles
            users_data = {}
            for username, profile in self._user_profiles.items():
                users_data[username] = {
                    "first_seen": profile.first_seen.isoformat(),
                    "last_seen": profile.last_seen.isoformat(),
                    "login_hours": dict(profile.login_hours),
                    "login_days": dict(profile.login_days),
                    "source_ips": list(profile.source_ips),
                    "actions": dict(profile.actions),
                    "hosts": list(profile.hosts),
                    "total_events": profile.total_events,
                }
            
            with open(self.baseline_path / "users.json", "w") as f:
                json.dump(users_data, f)
            
            # Save host profiles
            hosts_data = {}
            for hostname, profile in self._host_profiles.items():
                hosts_data[hostname] = {
                    "first_seen": profile.first_seen.isoformat(),
                    "last_seen": profile.last_seen.isoformat(),
                    "active_hours": dict(profile.active_hours),
                    "users": list(profile.users),
                    "processes": dict(profile.processes),
                    "total_events": profile.total_events,
                }
            
            with open(self.baseline_path / "hosts.json", "w") as f:
                json.dump(hosts_data, f)
            
            logger.info("Baselines saved")
        except Exception as e:
            logger.error(f"Failed to save baselines: {e}")
    
    def _load_baselines(self):
        """Load baselines from disk."""
        users_path = self.baseline_path / "users.json"
        hosts_path = self.baseline_path / "hosts.json"
        
        if users_path.exists():
            try:
                with open(users_path) as f:
                    users_data = json.load(f)
                
                for username, data in users_data.items():
                    profile = UserProfile(username=username)
                    profile.first_seen = datetime.fromisoformat(data["first_seen"])
                    profile.last_seen = datetime.fromisoformat(data["last_seen"])
                    profile.login_hours = defaultdict(int, {int(k): v for k, v in data.get("login_hours", {}).items()})
                    profile.login_days = defaultdict(int, {int(k): v for k, v in data.get("login_days", {}).items()})
                    profile.source_ips = set(data.get("source_ips", []))
                    profile.actions = defaultdict(int, data.get("actions", {}))
                    profile.hosts = set(data.get("hosts", []))
                    profile.total_events = data.get("total_events", 0)
                    self._user_profiles[username] = profile
                
                self._learning_mode = False
                logger.info(f"Loaded {len(self._user_profiles)} user profiles")
            except Exception as e:
                logger.error(f"Failed to load user baselines: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get baseline statistics."""
        return {
            "learning_mode": self._learning_mode,
            "events_processed": self._events_processed,
            "user_profiles": len(self._user_profiles),
            "host_profiles": len(self._host_profiles),
            "learning_days": self.learning_days,
            "min_events": self.min_events,
        }
