import json
import boto3
from rich.console import Console
import matplotlib.pyplot as plt
import argparse
import sys

console = Console()

RISKY_PHRASES = {
    "*": "Too broad - narrow it down",
    "iam:*": "IAM wildcards are bad news",
    "sts:*": "Limit STS usage",
    "lambda:*": "Lambda wildcard = too much trust",
    "ec2:*": "Scope EC2 actions",
    "s3:*": "S3 wildcard means all buckets exposed",
    "rds:*": "RDS wildcard covers admin stuff",
    "iam:CreateUser": "Only admins should do this",
    "iam:AttachUserPolicy": "Privilege escalation risk",
    "iam:PassRole": "Needs to be tightly scoped",
    "sts:AssumeRole": "Scope assumptions carefully"
}

class IAMChecker:
    def __init__(self):
        self.risk_order = ["safe", "low", "medium", "high", "critical"]

    def load_policy_file(self, path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("Can't find file:", path)
            sys.exit(1)
        except json.JSONDecodeError as e:
            print("Bad JSON format:", e)
            sys.exit(1)

    def _listify(self, item):
        # Quick helper
        if isinstance(item, str):
            return [item]
        elif isinstance(item, list):
            return item
        return []

    def check_risky_actions(self, actions):
        acts = self._listify(actions)
        for a in acts:
            if a.strip() in RISKY_PHRASES:
                return True, a.strip()
        return False, None

    def check_broad_resources(self, resources):
        res_list = self._listify(resources)
        for r in res_list:
            r = r.strip()
            if r == "*":
                return True, r
            if r.startswith("arn:aws:") and r.endswith("/*"):
                # rough heuristic - if it has 3 or fewer slashes, it's broad
                if r.count("/") <= 3:
                    return True, r
        return False, None

    def seems_readonly(self, actions):
        # quick way to guess
        readonly_keywords = ["Get", "List", "Describe", "Head", "View", "Select"]
        for a in self._listify(actions):
            if not any(k in a for k in readonly_keywords):
                return False
        return True

    def assess_risk(self, stmt):
        effect = stmt.get("Effect", "Allow")
        acts = stmt.get("Action", "")
        res = stmt.get("Resource", "")

        if effect == "Deny":
            return "safe", "Deny statement"

        risky, risky_act = self.check_risky_actions(acts)
        broad, broad_res = self.check_broad_resources(res)

        if risky and broad:
            return "critical", f"{risky_act} with {broad_res}"
        if risky:
            return "high", f"Risky action: {risky_act}"
        if broad and not self.seems_readonly(acts):
            return "medium", f"Write access to {broad_res}"
        if broad and self.seems_readonly(acts):
            return "low", f"Read-only to {broad_res}"

        # quick scan for write type words
        for a in self._listify(acts):
            if any(w in a.lower() for w in ["create", "delete", "put", "attach", "detach", "modify"]):
                return "medium", f"Write op: {a}"

        return "safe", "Looks fine"

    def analyze_policy(self, policy, threshold="medium"):
        flagged, all_results = [], []
        t_idx = self.risk_order.index(threshold)

        for stmt in policy.get("Statement", []):
            risk, reason = self.assess_risk(stmt)
            res = (stmt, risk, reason)
            all_results.append(res)
            if self.risk_order.index(risk) >= t_idx:
                flagged.append(res)

        return flagged, all_results

    def show_results(self, flagged, all_results):
        console.print("\n[bold blue]IAM Policy Analysis[/bold blue]")
        print(f"\nChecked {len(all_results)} statements, found {len(flagged)} issues")
        colors = {
            "safe": "green",
            "low": "yellow",
            "medium": "orange3",
            "high": "red3",
            "critical": "bold red"
        }
        for i, (stmt, risk, reason) in enumerate(all_results):
            console.print(f"\nStatement {i+1}: [{colors.get(risk,'white')}]{risk.upper()}[/{colors.get(risk,'white')}]")
            console.print(f"Reason: {reason}")
            console.print(f"Effect: {stmt.get('Effect', 'N/A')}")
            console.print(f"Action: {stmt.get('Action', 'N/A')}")
            console.print(f"Resource: {stmt.get('Resource', 'N/A')}")
            if risk in ["medium", "high", "critical"]:
                act = stmt.get("Action", "")
                if isinstance(act, list) and act:
                    act = act[0]
                fix = RISKY_PHRASES.get(act, "Probably tighten it up")
                console.print(f"[yellow]Fix: {fix}[/yellow]")

    def make_chart(self, results):
        if not results:
            return
        counts = {}
        for _, r, _ in results:
            counts[r] = counts.get(r, 0) + 1
        labels = list(counts.keys())
        values = list(counts.values())
        colormap = {
            "safe": "lightgreen",
            "low": "gold",
            "medium": "orange",
            "high": "lightcoral",
            "critical": "red"
        }
        plt.pie(values, labels=labels, colors=[colormap.get(l, "gray") for l in labels], autopct='%1.1f%%')
        plt.title("Risk Levels")
        plt.show()

    def get_aws_policies(self, kind, name):
        iam = boto3.client('iam')
        stmts = []
        try:
            if kind == "user":
                # inline
                for pname in iam.list_user_policies(UserName=name)['PolicyNames']:
                    stmts.extend(iam.get_user_policy(UserName=name, PolicyName=pname)['PolicyDocument'].get('Statement', []))
                # attached
                for pinfo in iam.list_attached_user_policies(UserName=name)['AttachedPolicies']:
                    meta = iam.get_policy(PolicyArn=pinfo['PolicyArn'])
                    vid = meta['Policy']['DefaultVersionId']
                    stmts.extend(iam.get_policy_version(PolicyArn=pinfo['PolicyArn'], VersionId=vid)['PolicyVersion']['Document'].get('Statement', []))
            elif kind == "role":
                # potenital change --> could refactor since this is similar to user
                for pname in iam.list_role_policies(RoleName=name)['PolicyNames']:
                    stmts.extend(iam.get_role_policy(RoleName=name, PolicyName=pname)['PolicyDocument'].get('Statement', []))
                for pinfo in iam.list_attached_role_policies(RoleName=name)['AttachedPolicies']:
                    meta = iam.get_policy(PolicyArn=pinfo['PolicyArn'])
                    vid = meta['Policy']['DefaultVersionId']
                    stmts.extend(iam.get_policy_version(PolicyArn=pinfo['PolicyArn'], VersionId=vid)['PolicyVersion']['Document'].get('Statement', []))
            elif kind == "group":
                for pname in iam.list_group_policies(GroupName=name)['PolicyNames']:
                    stmts.extend(iam.get_group_policy(GroupName=name, PolicyName=pname)['PolicyDocument'].get('Statement', []))
                for pinfo in iam.list_attached_group_policies(GroupName=name)['AttachedPolicies']:
                    meta = iam.get_policy(PolicyArn=pinfo['PolicyArn'])
                    vid = meta['Policy']['DefaultVersionId']
                    stmts.extend(iam.get_policy_version(PolicyArn=pinfo['PolicyArn'], VersionId=vid)['PolicyVersion']['Document'].get('Statement', []))
        except Exception as e:
            print("AWS error:", e)
            sys.exit(1)

        return {"Version": "2012-10-17", "Statement": stmts}

def main():
    parser = argparse.ArgumentParser(description="IAM Policy Checker")
    parser.add_argument('--file', '-f', help='Policy file (JSON)')
    parser.add_argument('--user')
    parser.add_argument('--role')
    parser.add_argument('--group')
    parser.add_argument('--threshold', choices=['low', 'medium', 'high'], default='medium')
    parser.add_argument('--no-chart', action='store_true')
    args = parser.parse_args()

    sources = [args.file, args.user, args.role, args.group]
    if sum(1 for s in sources if s) == 0:
        print("Interactive mode")
        print("1. File\n2. User\n3. Role\n4. Group")
        ch = input("Pick one: ").strip()
        if ch == "1":
            args.file = "example_policy.json"
        elif ch == "2":
            args.user = input("User: ").strip()
        elif ch == "3":
            args.role = input("Role: ").strip()
        elif ch == "4":
            args.group = input("Group: ").strip()
        else:
            print("Bad choice")
            return
    elif sum(1 for s in sources if s) > 1:
        print("Error: one source only")
        return

    checker = IAMChecker()

    try:
        if args.file:
            policy = checker.load_policy_file(args.file)
        elif args.user:
            policy = checker.get_aws_policies("user", args.user)
        elif args.role:
            policy = checker.get_aws_policies("role", args.role)
        elif args.group:
            policy = checker.get_aws_policies("group", args.group)

        flagged, all_results = checker.analyze_policy(policy, args.threshold)
        checker.show_results(flagged, all_results)
        if not args.no_chart:
            checker.make_chart(all_results)

        if not flagged:
            console.print("\n[green]No big problems found[/green]")
        else:
            console.print(f"\n[yellow]{len(flagged)} issues found[/yellow]")

    except KeyboardInterrupt:
        print("\nCancelled")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
