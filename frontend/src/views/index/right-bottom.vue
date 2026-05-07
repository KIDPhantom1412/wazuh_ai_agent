<script setup lang="ts">
import { ref, onMounted, nextTick } from "vue";
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid'; // 建议安装 uuid 库，或者用简单的随机数

const chatList = ref<any[]>([]);
const userInput = ref("");
const isTyping = ref(false);
const scrollRef = ref<HTMLElement | null>(null);

// --- 新增：会话 ID 管理 ---
// 确保在当前页面生命周期内，thread_id 是固定且唯一的
const sessionId = ref(`wazuh_session_${Math.random().toString(36).substr(2, 9)}`);

const handleSend = async () => {
  if (!userInput.value.trim() || isTyping.value) return;

  const msg = userInput.value;
  chatList.value.push({ role: 'user', content: msg });
  userInput.value = "";
  isTyping.value = true;
  
  await nextTick();
  scrollToBottom();

  try {
    const history = chatList.value.map(m => ({
      role: m.role,
      content: m.content
    }));
    const res = await axios.post('/agent-api/runs/wait', {
      assistant_id: "demo_agent",
      input: {
        messages: history
      },
      config: {
        configurable: { 
          // 关键：确保 thread_id 每次请求都一致且具有唯一性
          thread_id: sessionId.value 
        } 
      }
    }, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 90000 
    });

    let finalContent = "";
    // ... 原有的解析逻辑保持不变 ...
    if (res.data && Array.isArray(res.data.messages)) {
      const msgs = res.data.messages;
      const lastMsg = msgs[msgs.length - 1];
      if (lastMsg && lastMsg.content) {
        finalContent = typeof lastMsg.content === 'string' 
          ? lastMsg.content 
          : (Array.isArray(lastMsg.content) ? lastMsg.content[0]?.text : JSON.stringify(lastMsg.content));
      }
    }

    if (finalContent) {
      chatList.value.push({ role: 'assistant', content: finalContent });
    } else {
      chatList.value.push({ role: 'assistant', content: "⚠️ 未能解析到有效回复内容" });
    }

  } catch (error: any) {
    console.error('AI请求失败:', error);
    chatList.value.push({ role: 'assistant', content: `❌ 连接失败: ${error.message}` });
  } finally {
    isTyping.value = false;
    await nextTick();
    scrollToBottom();
  }
};

const scrollToBottom = () => {
  if (scrollRef.value) {
    scrollRef.value.scrollTop = scrollRef.value.scrollHeight;
  }
};
</script>

<template>

  <div class="ai_chat_container">

    <div class="chat_window" ref="scrollRef">

      <div

        v-for="(msg, index) in chatList"

        :key="index"

        :class="['msg_row', msg.role === 'user' ? 'row_user' : 'row_ai']"

      >

        <div class="avatar">{{ msg.role === 'user' ? 'Me' : 'AI' }}</div>

        <div class="content_box">

          <p class="text">{{ msg.content }}</p>

        </div>

      </div>

      <div v-if="isTyping" class="typing">AI 正在分析中...</div>

    </div>



    <div class="input_area">

      <input

        v-model="userInput"

        type="text"

        placeholder="输入安全指令或咨询告警..."

        @keyup.enter="handleSend"

      />

      <button @click="handleSend">发送</button>

    </div>

  </div>

</template>



<style scoped lang="scss">

.ai_chat_container {

  display: flex;

  flex-direction: column;

  height: 100%;

  background: rgba(0, 20, 40, 0.4);

  border-radius: 4px;

  padding: 10px;



  .chat_window {

    flex: 1;

    overflow-y: auto;

    padding-right: 5px;

    margin-bottom: 10px;



    /* 隐藏滚动条样式 */

    &::-webkit-scrollbar { width: 4px; }

    &::-webkit-scrollbar-thumb { background: #31ABE3; border-radius: 2px; }



    .msg_row {

      display: flex;

      margin-bottom: 15px;

      animation: fadeIn 0.3s ease;



      .avatar {

        width: 30px;

        height: 30px;

        border-radius: 50%;

        font-size: 10px;

        line-height: 30px;

        text-align: center;

        margin-right: 10px;

        flex-shrink: 0;

      }



      .content_box {

        max-width: 85%;

        padding: 8px 12px;

        border-radius: 8px;

        font-size: 13px;

        line-height: 1.5;

      }

    }



    .row_ai {

      .avatar { background: #31ABE3; color: #fff; }

      .content_box { background: rgba(49, 171, 227, 0.1); border: 1px solid rgba(49, 171, 227, 0.3); color: #fff; }

    }



    .row_user {

      flex-direction: row-reverse;

      .avatar { background: #00fdfa; color: #000; margin-right: 0; margin-left: 10px; }

      .content_box { background: rgba(0, 253, 250, 0.1); border: 1px solid rgba(0, 253, 250, 0.3); color: #fff; }

    }

  }



  .typing { font-size: 12px; color: #31ABE3; margin-bottom: 10px; font-style: italic; }



  .input_area {

    display: flex;

    gap: 8px;

    height: 40px;



    input {

      flex: 1;

      background: rgba(255, 255, 255, 0.05);

      border: 1px solid rgba(49, 171, 227, 0.5);

      border-radius: 4px;

      color: #fff;

      padding: 0 10px;

      outline: none;

      &:focus { border-color: #00fdfa; }

    }



    button {

      width: 60px;

      background: #31ABE3;

      border: none;

      border-radius: 4px;

      color: #fff;

      cursor: pointer;

      &:hover { background: #00fdfa; color: #000; }

    }

  }

}



@keyframes fadeIn {

  from { opacity: 0; transform: translateY(5px); }

  to { opacity: 1; transform: translateY(0); }

}

</style>