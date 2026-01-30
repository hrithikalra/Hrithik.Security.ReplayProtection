
---

# 6️⃣ Versioning Strategy (Follow this strictly)

| Change | Version |
|------|--------|
| Initial release | `1.0.0` |
| Backward compatible features | `1.1.0` |
| Bug fixes | `1.0.1` |
| Breaking changes | `2.0.0` |

---

# 7️⃣ First Publish Checklist ✅

Before publishing:
- [ ] Project builds
- [ ] README visible in NuGet
- [ ] No unused public APIs
- [ ] XML comments on public classes
- [ ] Strong defaults

Publish:
```bash
dotnet pack -c Release
dotnet nuget push bin/Release/*.nupkg -k YOUR_API_KEY -s https://api.nuget.org/v3/index.json
