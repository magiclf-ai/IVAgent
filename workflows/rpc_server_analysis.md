---
name: "RPC 程序漏洞挖掘"
description: 无
version: "1.0"
strategy_hints:
  max_depth: "建议调用链深度为 3-5 层"
  concurrency: "可根据函数数量动态决定并发度"
---

## 分析步骤

从二进制中分析 handle_type_xxx (由于是 c++ 程序，实际搜索应该为 `.*handle_type.*`) 命名的函数，他们会处理用户输入，挖掘其中的漏洞

```c
// ============================================
void dispatch_message(const RpcMessage* msg) {
    size_t payload_len = msg->header.data_len;
    const uint8_t* payload = msg->payload;
    
    switch (msg->header.msg_type) {
        case MSG_TYPE_1:  handle_type_1(payload, payload_len); break;
        case MSG_TYPE_2:  handle_type_2(payload, payload_len); break;
        case MSG_TYPE_3:  handle_type_3(payload, payload_len); break;
        case MSG_TYPE_4:  handle_type_4(payload, payload_len); break;
        case MSG_TYPE_5:  handle_type_5(payload, payload_len); break;
        case MSG_TYPE_6:  handle_type_6(payload, payload_len); break;
        case MSG_TYPE_7:  handle_type_7(payload, payload_len); break;
        case MSG_TYPE_8:  handle_type_8(payload, payload_len); break;
        case MSG_TYPE_9:  handle_type_9(payload, payload_len); break;
        case MSG_TYPE_10: handle_type_10(payload, payload_len); break;
        case MSG_TYPE_11: handle_type_11(payload, payload_len); break;
        case MSG_TYPE_12: handle_type_12(payload, payload_len); break;
        case MSG_TYPE_13: handle_type_13(payload, payload_len); break;
        case MSG_TYPE_14: handle_type_14(payload, payload_len); break;
        case MSG_TYPE_15: handle_type_15(payload, payload_len); break;
        case MSG_TYPE_16: handle_type_16(payload, payload_len); break;
        case MSG_TYPE_17: handle_type_17(payload, payload_len); break;
        case MSG_TYPE_18: handle_type_18(payload, payload_len); break;
        case MSG_TYPE_19: handle_type_19(payload, payload_len); break;
        case MSG_TYPE_20: handle_type_20(payload, payload_len); break;
        default:
            printf("Unknown message type: %u\n", msg->header.msg_type);
            break;
    }
}
```
