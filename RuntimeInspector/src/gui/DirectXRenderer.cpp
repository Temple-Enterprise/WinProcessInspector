#include "DirectXRenderer.h"
#include "../core/Logger.h"
#include <d3dcompiler.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")

namespace RuntimeInspector {
namespace GUI {

DirectXRenderer::DirectXRenderer() : m_hWnd(nullptr) {
}

DirectXRenderer::~DirectXRenderer() {
	Shutdown();
}

bool DirectXRenderer::Initialize(HWND hWnd) {
	m_hWnd = hWnd;
	
	DXGI_SWAP_CHAIN_DESC sd = {};
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	
	UINT createDeviceFlags = 0;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
	
	ID3D11Device* device = nullptr;
	ID3D11DeviceContext* context = nullptr;
	IDXGISwapChain* swapChain = nullptr;
	
	HRESULT hr = D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		createDeviceFlags,
		featureLevelArray,
		2,
		D3D11_SDK_VERSION,
		&sd,
		&swapChain,
		&device,
		&featureLevel,
		&context
	);
	
	if (FAILED(hr)) {
		Core::Logger::GetInstance().LogError("Failed to create DirectX device and swap chain");
		return false;
	}
	
	m_Device.reset(device);
	m_Context.reset(context);
	m_SwapChain.reset(swapChain);
	
	CreateRenderTarget();
	
	Core::Logger::GetInstance().LogInfo("DirectX renderer initialized");
	return true;
}

void DirectXRenderer::Shutdown() {
	CleanupRenderTarget();
	m_RenderTargetView.reset();
	m_SwapChain.reset();
	m_Context.reset();
	m_Device.reset();
	m_hWnd = nullptr;
}

void DirectXRenderer::BeginFrame() {
	if (!m_Context || !m_RenderTargetView) {
		return;
	}
	
	ID3D11RenderTargetView* rtv = m_RenderTargetView.get();
	m_Context->OMSetRenderTargets(1, &rtv, nullptr);
}

void DirectXRenderer::ClearRenderTarget(const float color[4]) {
	if (!m_Context || !m_RenderTargetView) {
		return;
	}
	
	ID3D11RenderTargetView* rtv = m_RenderTargetView.get();
	m_Context->ClearRenderTargetView(rtv, color);
}

void DirectXRenderer::EndFrame() {
	if (!m_SwapChain) {
		return;
	}
	
	m_SwapChain->Present(1, 0);
}

void DirectXRenderer::Resize(UINT width, UINT height) {
	if (!m_SwapChain || !m_Device) {
		return;
	}
	
	CleanupRenderTarget();
	
	HRESULT hr = m_SwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
	if (FAILED(hr)) {
		Core::Logger::GetInstance().LogError("Failed to resize swap chain buffers");
		return;
	}
	
	CreateRenderTarget();
}

void DirectXRenderer::CreateRenderTarget() {
	if (!m_SwapChain || !m_Device) {
		return;
	}
	
	ID3D11Texture2D* pBackBuffer = nullptr;
	if (SUCCEEDED(m_SwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) && pBackBuffer) {
		ID3D11RenderTargetView* pRenderTargetView = nullptr;
		if (SUCCEEDED(m_Device->CreateRenderTargetView(pBackBuffer, nullptr, &pRenderTargetView))) {
			m_RenderTargetView.reset(pRenderTargetView);
		}
		pBackBuffer->Release();
	}
}

void DirectXRenderer::CleanupRenderTarget() {
	m_RenderTargetView.reset();
}

void* DirectXRenderer::CreateTextureFromIcon(HICON hIcon) {
	if (!hIcon || !m_Device) {
		return nullptr;
	}
	
	ICONINFO iconInfo = {};
	if (!GetIconInfo(hIcon, &iconInfo)) {
		return nullptr;
	}
	
	BITMAP bmp = {};
	if (!GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmp)) {
		if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
		if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
		return nullptr;
	}
	
	int width = bmp.bmWidth;
	int height = bmp.bmHeight;
	
	HDC hDC = CreateCompatibleDC(nullptr);
	BITMAPINFO bmi = {};
	bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmi.bmiHeader.biWidth = width;
	bmi.bmiHeader.biHeight = -height;
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;
	
	unsigned int* pixels = nullptr;
	HBITMAP hBitmap = CreateDIBSection(hDC, &bmi, DIB_RGB_COLORS, (void**)&pixels, nullptr, 0);
	if (!hBitmap) {
		DeleteDC(hDC);
		if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
		if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
		return nullptr;
	}
	
	memset(pixels, 0, width * height * 4);
	
	HBITMAP hOldBitmap = (HBITMAP)SelectObject(hDC, hBitmap);
	DrawIconEx(hDC, 0, 0, hIcon, width, height, 0, nullptr, DI_NORMAL);
	SelectObject(hDC, hOldBitmap);
	DeleteDC(hDC);
	
	unsigned int* rgbaPixels = new unsigned int[width * height];
	for (int i = 0; i < width * height; i++) {
		unsigned int pixel = pixels[i];
		unsigned char b = (pixel >> 0) & 0xFF;
		unsigned char g = (pixel >> 8) & 0xFF;
		unsigned char r = (pixel >> 16) & 0xFF;
		unsigned char a = (pixel >> 24) & 0xFF;
		rgbaPixels[i] = (a << 24) | (b << 16) | (g << 8) | r;
	}
	DeleteObject(hBitmap);
	
	D3D11_TEXTURE2D_DESC desc = {};
	desc.Width = width;
	desc.Height = height;
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	desc.SampleDesc.Count = 1;
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	desc.CPUAccessFlags = 0;
	
	D3D11_SUBRESOURCE_DATA subResource = {};
	subResource.pSysMem = rgbaPixels;
	subResource.SysMemPitch = width * 4;
	subResource.SysMemSlicePitch = 0;
	
	ID3D11Texture2D* pTexture = nullptr;
	if (FAILED(m_Device->CreateTexture2D(&desc, &subResource, &pTexture))) {
		delete[] rgbaPixels;
		if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
		if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
		return nullptr;
	}
	delete[] rgbaPixels;
	
	D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
	srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
	srvDesc.Texture2D.MipLevels = 1;
	srvDesc.Texture2D.MostDetailedMip = 0;
	
	ID3D11ShaderResourceView* pSRV = nullptr;
	if (FAILED(m_Device->CreateShaderResourceView(pTexture, &srvDesc, &pSRV))) {
		pTexture->Release();
		if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
		if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
		return nullptr;
	}
	
	pTexture->Release();
	if (iconInfo.hbmColor) DeleteObject(iconInfo.hbmColor);
	if (iconInfo.hbmMask) DeleteObject(iconInfo.hbmMask);
	
	return (void*)pSRV;
}

void DirectXRenderer::ReleaseTexture(void* texture) {
	if (texture) {
		ID3D11ShaderResourceView* pSRV = (ID3D11ShaderResourceView*)texture;
		pSRV->Release();
	}
}

}
}
