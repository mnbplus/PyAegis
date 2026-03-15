# PyAegis Publisher Loop - runs forever, checks every 5 minutes
$repoPath = 'D:\Github项目\PyAegis'
$failureLog = Join-Path $repoPath 'REVIEW_FAILURES.md'

while ($true) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] Checking for unpushed commits..."

    $unpushed = & git -C $repoPath log origin/main..HEAD --oneline 2>&1
    $unpushedStr = ($unpushed | Out-String).Trim()

    if ($unpushedStr -ne '') {
        Write-Host "[$ts] Found unpushed commits:"
        Write-Host $unpushedStr

        # Run tests
        Write-Host "[$ts] Running pytest..."
        $testOut = & python -m pytest tests/ -q 2>&1
        $testOutStr = ($testOut | Out-String).Trim()
        $testLast = ($testOut | Select-Object -Last 3 | Out-String).Trim()
        Write-Host $testLast
        $testFail = $testOutStr -match '(?i)\bfailed\b|\d+ error'

        # Run lint
        Write-Host "[$ts] Running ruff..."
        $lintOut = & python -m ruff check . --ignore E501 --statistics 2>&1
        $lintOutStr = ($lintOut | Out-String).Trim()
        $lintLast = ($lintOut | Select-Object -Last 5 | Out-String).Trim()
        Write-Host $lintLast
        # Only block on ruff ERROR lines (e.g. "error: Failed to..."), not lint warnings
        $lintError = ($lintOut | Where-Object { $_ -match '^error:' }) -ne $null -and ($lintOut | Where-Object { $_ -match '^error:' }).Count -gt 0

        if (-not $testFail -and -not $lintError) {
            Write-Host "[$ts] All checks passed. Pushing to origin/main..."
            $pushOut = & git -C $repoPath push origin main 2>&1 | Out-String
            Write-Host $pushOut.Trim()
        } else {
            Write-Host "[$ts] Checks FAILED. Writing to REVIEW_FAILURES.md"
            $report = "## Review Failure at $ts`r`n`r`n### Unpushed Commits`r`n$unpushedStr`r`n`r`n### Test Output`r`n$testLast`r`n`r`n### Lint Output`r`n$lintLast`r`n`r`n---`r`n"
            Add-Content -Path $failureLog -Value $report
        }
    } else {
        Write-Host "[$ts] No unpushed commits."
    }

    Write-Host "[$ts] Sleeping 5 minutes..."
    Start-Sleep -Seconds 300
}
