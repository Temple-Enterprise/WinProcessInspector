#pragma once

#include <d3d11.h>
#include <dxgi.h>
#include <Windows.h>
#include <memory>

namespace RuntimeInspector {
namespace GUI {

class DirectXRenderer {
public:
	DirectXRenderer();
	~DirectXRenderer();
	
	DirectXRenderer(const DirectXRenderer&) = delete;
	DirectXRenderer& operator=(const DirectXRenderer&) = delete;
	
	bool Initialize(HWND hWnd);
	void Shutdown();
	
	void BeginFrame();
	void EndFrame();
	void ClearRenderTarget(const float color[4]);
	
	void Resize(UINT width, UINT height);
	
	ID3D11Device* GetDevice() const { return m_Device.get(); }
	ID3D11DeviceContext* GetContext() const { return m_Context.get(); }
	
	void* CreateTextureFromIcon(HICON hIcon);
	void ReleaseTexture(void* texture);
	
private:
	void CreateRenderTarget();
	void CleanupRenderTarget();
	
	struct ComDeleter {
		template<typename T>
		void operator()(T* ptr) {
			if (ptr) {
				ptr->Release();
			}
		}
	};
	
	using DevicePtr = std::unique_ptr<ID3D11Device, ComDeleter>;
	using ContextPtr = std::unique_ptr<ID3D11DeviceContext, ComDeleter>;
	using SwapChainPtr = std::unique_ptr<IDXGISwapChain, ComDeleter>;
	
	HWND m_hWnd;
	DevicePtr m_Device;
	ContextPtr m_Context;
	SwapChainPtr m_SwapChain;
	RenderTargetPtr m_RenderTargetView;
};

}
}
