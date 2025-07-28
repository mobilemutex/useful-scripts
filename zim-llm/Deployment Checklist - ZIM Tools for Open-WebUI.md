# Deployment Checklist - ZIM Tools for Open-WebUI

Use this checklist to ensure successful deployment of ZIM Tools in your Open-WebUI environment.

## Pre-Deployment Preparation

### ✅ Environment Verification

- [ ] **Open-WebUI Version**: Confirm version 0.4.0 or higher
  ```bash
  # Check Open-WebUI version in the interface or logs
  docker logs open-webui | grep version
  ```

- [ ] **System Resources**: Verify adequate resources
  - [ ] **RAM**: 4GB+ available (8GB+ for large ZIM files)
  - [ ] **Storage**: Sufficient space for ZIM files (varies by archive)
  - [ ] **CPU**: Multi-core recommended for search operations

- [ ] **Network Access**: Ensure connectivity for ZIM file downloads
  - [ ] Access to https://download.kiwix.org/
  - [ ] Sufficient bandwidth for large file downloads

### ✅ File Preparation

- [ ] **Tool File**: Validate `zim_tools.py`
  ```bash
  python3 validate_tool_compatibility.py
  ```

- [ ] **Dependencies**: Confirm dependency availability
  ```bash
  pip install --dry-run libzim>=3.5 strip-tags>=0.6
  ```

- [ ] **ZIM Directory**: Prepare storage location
  ```bash
  mkdir -p /data/zim
  chmod 755 /data/zim
  ```

## Deployment Steps

### ✅ Phase 1: Tool Installation

- [ ] **Install Tool in Open-WebUI**
  - [ ] Navigate to Workspace > Tools
  - [ ] Click + Add Tool
  - [ ] Paste `zim_tools.py` content
  - [ ] Click Save
  - [ ] Verify no error messages

- [ ] **Dependency Installation**
  - [ ] Dependencies auto-install (preferred)
  - [ ] OR manual installation if needed:
    ```bash
    pip install libzim>=3.5 strip-tags>=0.6
    ```

- [ ] **Tool Validation**
  - [ ] Tool appears in tools list
  - [ ] No error indicators
  - [ ] Settings accessible

### ✅ Phase 2: ZIM Files Setup

- [ ] **Download Initial ZIM Files**
  - [ ] Start with small test file (Simple Wikipedia ~250MB)
  - [ ] Download relevant archives for your use case
  - [ ] Verify file integrity (no corruption)

- [ ] **File Organization**
  ```bash
  # Verify files are accessible
  ls -la /data/zim/*.zim
  
  # Check file permissions
  chmod 644 /data/zim/*.zim
  ```

- [ ] **Environment Configuration**
  ```bash
  # Set KIWIX_HOME if needed
  export KIWIX_HOME=/data/zim
  ```

### ✅ Phase 3: Tool Configuration

- [ ] **Access Tool Settings**
  - [ ] Go to Workspace > Tools
  - [ ] Find "ZIM Archive Tools"
  - [ ] Click settings icon

- [ ] **Configure Basic Settings**
  - [ ] Set `zim_directory` to ZIM file location
  - [ ] Set `max_search_results` (start with 3)
  - [ ] Enable `enable_citations` (recommended)
  - [ ] Enable `enable_status_updates` (recommended)

- [ ] **Save Configuration**
  - [ ] Click Save
  - [ ] Verify settings persist

### ✅ Phase 4: Model Integration

- [ ] **Enable Tool for Models**
  - [ ] Go to Workspace > Models
  - [ ] For each relevant model:
    - [ ] Click edit icon
    - [ ] Scroll to Tools section
    - [ ] Check "ZIM Archive Tools"
    - [ ] Save changes

- [ ] **Test Model Configuration**
  - [ ] Start new chat with enabled model
  - [ ] Verify tool appears in available tools list

## Testing and Validation

### ✅ Phase 5: Functional Testing

- [ ] **Basic Functionality Test**
  ```
  Test prompt: "What offline resources do you have access to?"
  Expected: List of available ZIM files with metadata
  ```

- [ ] **Search Functionality Test**
  ```
  Test prompt: "Search for information about [topic] in the available archives"
  Expected: Relevant search results with content
  ```

- [ ] **Citation Verification**
  - [ ] Citations appear in chat
  - [ ] Source information is accurate
  - [ ] Links reference correct ZIM files

- [ ] **Error Handling Test**
  ```
  Test prompt: "Search for xyz123nonexistent in the archives"
  Expected: Graceful "no results found" message
  ```

### ✅ Phase 6: Performance Testing

- [ ] **Response Time Testing**
  - [ ] Search operations complete within 30 seconds
  - [ ] Content retrieval completes within 60 seconds
  - [ ] No timeout errors

- [ ] **Resource Usage Monitoring**
  ```bash
  # Monitor during testing
  htop
  df -h
  ```

- [ ] **Large File Testing** (if applicable)
  - [ ] Test with largest available ZIM file
  - [ ] Verify performance remains acceptable
  - [ ] Check memory usage stays within limits

## Production Deployment

### ✅ Phase 7: Production Readiness

- [ ] **Backup Configuration**
  ```bash
  # Backup tool file
  cp zim_tools.py ~/backups/zim_tools_$(date +%Y%m%d).py
  
  # Document configuration settings
  ```

- [ ] **Security Review**
  - [ ] File permissions are appropriate
  - [ ] Tool access is limited to authorized users
  - [ ] No sensitive information in configuration

- [ ] **Documentation**
  - [ ] User guide available for team
  - [ ] Configuration documented
  - [ ] Troubleshooting procedures documented

### ✅ Phase 8: User Training

- [ ] **Create User Guide**
  - [ ] Example conversation patterns
  - [ ] Available ZIM archives and their content
  - [ ] Best practices for search queries

- [ ] **Conduct Training Session**
  - [ ] Demonstrate tool capabilities
  - [ ] Show example conversations
  - [ ] Address user questions

- [ ] **Gather Feedback**
  - [ ] Monitor initial usage
  - [ ] Collect user feedback
  - [ ] Identify improvement opportunities

## Post-Deployment Monitoring

### ✅ Phase 9: Ongoing Maintenance

- [ ] **Regular Health Checks**
  ```bash
  # Weekly validation
  python3 validate_tool_compatibility.py
  ```

- [ ] **ZIM File Updates**
  - [ ] Monthly check for updated archives
  - [ ] Download and replace outdated files
  - [ ] Clean up old versions

- [ ] **Performance Monitoring**
  - [ ] Monitor response times
  - [ ] Check resource usage trends
  - [ ] Address performance issues

- [ ] **User Support**
  - [ ] Monitor for user issues
  - [ ] Provide ongoing support
  - [ ] Update documentation as needed

## Rollback Plan

### ✅ Emergency Procedures

- [ ] **Tool Rollback**
  - [ ] Disable tool in model settings
  - [ ] Remove tool from Open-WebUI
  - [ ] Restore previous configuration

- [ ] **Backup Restoration**
  ```bash
  # Restore from backup
  cp ~/backups/zim_tools_YYYYMMDD.py zim_tools.py
  ```

- [ ] **Communication Plan**
  - [ ] Notify users of issues
  - [ ] Provide alternative resources
  - [ ] Communicate resolution timeline

## Success Criteria

### ✅ Deployment Success Indicators

- [ ] **Functional Success**
  - [ ] All tool functions work correctly
  - [ ] Search returns relevant results
  - [ ] Citations are properly displayed
  - [ ] Error handling works gracefully

- [ ] **Performance Success**
  - [ ] Response times meet expectations
  - [ ] Resource usage is acceptable
  - [ ] No system stability issues

- [ ] **User Success**
  - [ ] Users can successfully use the tools
  - [ ] Positive feedback from initial users
  - [ ] No major usability issues

- [ ] **Integration Success**
  - [ ] Tool integrates seamlessly with Open-WebUI
  - [ ] Works with all enabled models
  - [ ] No conflicts with other tools

## Troubleshooting Quick Reference

### Common Issues and Solutions

| Issue | Quick Fix |
|-------|-----------|
| Tool not appearing | Check Open-WebUI version, reinstall tool |
| Dependencies failing | Manual pip install, check network |
| ZIM files not found | Verify path, check permissions |
| Search returns no results | Try different terms, check ZIM integrity |
| Performance issues | Reduce max_search_results, check resources |
| Citations not showing | Enable citations in tool settings |

### Emergency Contacts

- **System Administrator**: [Contact Info]
- **Open-WebUI Support**: [Documentation/Community]
- **Tool Developer**: [GitHub Issues/Contact]

## Completion Sign-off

- [ ] **Technical Lead Approval**: _________________ Date: _______
- [ ] **Security Review Complete**: _________________ Date: _______
- [ ] **User Training Complete**: _________________ Date: _______
- [ ] **Documentation Updated**: _________________ Date: _______
- [ ] **Deployment Successful**: _________________ Date: _______

---

**Deployment Notes:**
_Use this space to document any specific considerations, customizations, or issues encountered during deployment._

**Next Review Date:** _________________

