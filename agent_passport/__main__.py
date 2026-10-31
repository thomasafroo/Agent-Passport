import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Run Agent Passport's local incident console")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    uvicorn.run("agent_passport.server:create_app", factory=True, host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
