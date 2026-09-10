# Contributing to cai-osint

Thanks for your interest in contributing! 🛡️

## Getting Started
1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/cai-osint.git`
3. Create a feature branch: `git checkout -b feat/my-feature`
4. Install dependencies: `pip install -r requirements.txt`
5. Test the server: `python -c "from server import mcp; print('OK')"`
6. Commit with conventional commits: `git commit -m "feat: add new feature"`
7. Push and create a Pull Request

## Development Setup
```bash
pip install -r requirements.txt
python demo_runner.py scanme.nmap.org   # Run live demo
python server.py                         # Start MCP server
```

## Code Standards
- Use Python stdlib for recon (socket, ssl, http.client) — no nmap/shodan dependencies
- Type hints on all function signatures
- Rate-limit all network scanning (max 5 concurrent connections)
- All new MCP tools must include docstrings for agent discovery

## Adding a New Recon Module
1. Add the method to `app/recon.py` in `OSINTReconEngine`
2. Expose it as an MCP tool in `server.py` using `@mcp.tool()`
3. Include findings integration in `evaluate_posture()`
4. Update `demo_runner.py` to showcase the new step

## Commit Convention
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation only
- `chore:` — Maintenance tasks

## ⚠️ Ethical Guidelines
- Only scan targets you have explicit permission to test
- Default demo target is `scanme.nmap.org` (public test server)
- Never include credential-based or authenticated scanning
