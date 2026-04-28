import type { TodoItem } from '../types'

import { client as fetch } from './secure-fetch'

export async function listTodos(): Promise<TodoItem[]> {
	const response = await fetch.get('/api/todos')
	return Array.isArray(response?.items) ? response.items : []
}

export async function createTodo(input: {
	title: string
	description: string
	image_data_url?: string
	image_content_type?: string
}): Promise<TodoItem> {
	return fetch.post('/api/todos', input)
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
	return fetch.put(`/api/todos/${encodeURIComponent(id)}`, input)
}

export async function deleteTodo(id: string): Promise<{ success: boolean }> {
	return fetch.delete(`/api/todos/${encodeURIComponent(id)}`)
}
