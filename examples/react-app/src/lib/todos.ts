import type { TodoItem } from '../types'

import { secureHttpClient } from './secure-http'

export async function listTodos(): Promise<TodoItem[]> {
  const response = await secureHttpClient.get('/api/todos')
  return Array.isArray(response?.items) ? response.items : []
}

export async function createTodo(input: {
  title: string
  description: string
  image_data_url?: string
  image_content_type?: string
}): Promise<TodoItem> {
  return secureHttpClient.post('/api/todos', input)
}

export async function updateTodo(
  id: string,
  input: {
    title: string
    description: string
    done: boolean
    image_data_url?: string
    image_content_type?: string
  },
): Promise<TodoItem> {
  return secureHttpClient.put(`/api/todos/${encodeURIComponent(id)}`, input)
}

export async function deleteTodo(id: string): Promise<{ success: boolean }> {
  return secureHttpClient.delete(`/api/todos/${encodeURIComponent(id)}`)
}
