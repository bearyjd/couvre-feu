const mode = process.argv[2];
if (mode === 'exit' || mode === 'exit255') process.exit(255);
if (mode === 'exit2') process.exit(2);
if (mode === 'invalid-command') { process.stdout.write('{"ok":false,"errors":["invalid_command"]}\n'); process.exit(2); }
if (mode === 'truncated') process.stdout.write('{"rpc_version":1');
else if (mode === 'oversize') process.stdout.write('x'.repeat(131073));
else if (mode === 'diagnostics') process.stderr.write('PRIVATE_DIAGNOSTIC'.repeat(2000));
else if (mode === 'delay') { process.on('SIGTERM', () => {}); setTimeout(() => {}, 10000); }
else if (mode === 'environment') process.stdout.write(`${process.env.CF_TEST_PUBLIC}:${process.env.SSH_ASKPASS ?? 'absent'}`);
else if (mode === 'echo' || mode === 'echo-nonzero') {
    const chunks: Buffer[] = []; for await (const chunk of process.stdin) chunks.push(chunk);
    process.stdout.write(Buffer.concat(chunks)); if (mode === 'echo-nonzero') process.exitCode = 1;
}
