import asyncio
async def main():
    cmd = "ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@10.221.66.27 'echo hello'"
    process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    print('STDOUT:', stdout)
    print('STDERR:', stderr)
asyncio.run(main())
